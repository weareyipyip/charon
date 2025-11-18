defmodule Charon.TokenPlugsTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  alias Charon.{Utils, Internal, TokenPlugs, SessionStore}
  import Charon.TestUtils
  import Utils
  import Plug.Conn
  import Plug.Test
  import TokenPlugs
  alias TokenPlugs.PutAssigns
  alias Charon.Models.Session

  @config Charon.TestConfig.get()

  def sign(payload), do: Charon.TokenFactory.Jwt.sign(payload, @config) |> elem(1)

  def verify_read_scope(conn, value) do
    if "read" in String.split(value, ",") do
      conn
    else
      "no read scope"
    end
  end

  def telemetry_handler(event_name, measurements, metadata, _config) do
    send(self(), {:telemetry, event_name, measurements, metadata})
  end

  setup do
    start_supervised!(Charon.SessionStore.LocalStore)

    # Subscribe to token telemetry events
    :telemetry.attach_many(
      "token-test-handler",
      [
        [:charon, :token, :valid],
        [:charon, :token, :invalid]
      ],
      &__MODULE__.telemetry_handler/4,
      nil
    )

    on_exit(fn -> :telemetry.detach("token-test-handler") end)

    :ok
  end

  describe "emit_telemetry/2" do
    test "emits valid token event with minimal metadata when no token payload or session" do
      _conn =
        conn()
        |> put_private(@token_transport, :bearer)
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: false,
               token_transport: :bearer
             }
    end

    test "emits valid token event with full metadata when token payload is present" do
      _conn =
        conn()
        |> put_private(@token_transport, :cookie)
        |> set_token_payload(%{
          "type" => "access",
          "sub" => 123,
          "sid" => "session-123",
          "styp" => "full"
        })
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: false,
               token_transport: :cookie,
               token_type: "access",
               user_id: 123,
               session_id: "session-123",
               session_type: "full"
             }
    end

    test "emits valid token event with session_loaded=true when session is present" do
      session = test_session(user_id: 456, id: "session-456")

      _conn =
        conn()
        |> put_private(@token_transport, :cookie_only)
        |> put_private(@session, session)
        |> set_token_payload(%{
          "type" => "refresh",
          "sub" => 456,
          "sid" => "session-456",
          "styp" => "full"
        })
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: true,
               token_transport: :cookie_only,
               token_type: "refresh",
               user_id: 456,
               session_id: "session-456",
               session_type: "full"
             }
    end

    test "emits invalid token event with error when auth error is present" do
      _conn =
        conn()
        |> put_private(@token_transport, :bearer)
        |> set_auth_error("bearer token signature invalid")
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :invalid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: false,
               token_transport: :bearer,
               error: "bearer token signature invalid"
             }
    end

    test "emits invalid token event with full metadata when token payload is present" do
      _conn =
        conn()
        |> put_private(@token_transport, :cookie)
        |> set_token_payload(%{
          "type" => "refresh",
          "sub" => 789,
          "sid" => "expired-session",
          "styp" => "oauth2"
        })
        |> set_auth_error("bearer token expired")
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :invalid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: false,
               token_transport: :cookie,
               error: "bearer token expired",
               token_type: "refresh",
               user_id: 789,
               session_id: "expired-session",
               session_type: "oauth2"
             }
    end

    test "emits invalid token event with session loaded" do
      session = test_session(user_id: 999, id: "session-999")

      _conn =
        conn()
        |> put_private(@token_transport, :bearer)
        |> put_private(@session, session)
        |> set_token_payload(%{
          "type" => "access",
          "sub" => 999,
          "sid" => "session-999",
          "styp" => "full"
        })
        |> set_auth_error("token stale")
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :invalid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               session_loaded: true,
               token_transport: :bearer,
               error: "token stale",
               token_type: "access",
               user_id: 999,
               session_id: "session-999",
               session_type: "full"
             }
    end

    test "returns conn unchanged" do
      conn =
        conn()
        |> put_private(@token_transport, :bearer)
        |> set_token_payload(%{"type" => "access", "sub" => 1, "sid" => "s1", "styp" => "full"})

      result = emit_telemetry(conn, [])

      assert result == conn
    end

    test "handles nil token_transport" do
      _conn =
        conn()
        |> set_token_payload(%{"type" => "access", "sub" => 1, "sid" => "s1", "styp" => "full"})
        |> emit_telemetry([])

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, metadata}
      assert measurements == %{count: 1}

      assert metadata == %{
               token_transport: nil,
               session_loaded: false,
               token_type: "access",
               user_id: 1,
               session_id: "s1",
               session_type: "full"
             }
    end
  end

  describe "get_token_from_cookie/2" do
    test "is backwards compatible with old splitting style header.payload. <> signature" do
      conn =
        conn()
        |> put_private(@bearer_token, "token.")
        |> put_private(@token_transport, :bearer)
        |> put_req_cookie("c", "sig")
        |> fetch_cookies()
        |> get_token_from_cookie("c")

      assert "token.sig" == Utils.get_bearer_token(conn)
      assert :cookie == Utils.get_token_transport(conn)
    end

    test "ignores cookie in other cases" do
      conn =
        conn()
        |> put_private(@bearer_token, "token")
        |> put_private(@token_transport, :bearer)
        |> put_req_cookie("c", "sig")
        |> fetch_cookies()
        |> get_token_from_cookie("c")

      assert "token" == Utils.get_bearer_token(conn)
      assert :bearer == Utils.get_token_transport(conn)
    end
  end

  doctest TokenPlugs
  doctest PutAssigns
end
