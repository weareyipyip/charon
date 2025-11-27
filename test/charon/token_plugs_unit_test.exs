defmodule Charon.TokenPlugsTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  alias Charon.{Utils, Internal, TokenPlugs, SessionStore, TokenFactory}
  import Charon.TestUtils
  import Utils
  import Plug.Conn
  import Plug.Test
  import TokenPlugs
  alias Charon.Models.Session

  @config TestApp.Charon.get()

  def sign(payload), do: TokenFactory.Jwt.sign(payload, @config) |> elem(1)

  def verify_read_scope(conn, value) do
    if "read" in String.split(value, ","), do: conn, else: "no read scope"
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
    test "uses cookie as full token when no bearer token was found" do
      conn =
        conn()
        |> put_req_cookie("access_cookie", "full.token.here")
        |> fetch_cookies()
        |> get_token_from_cookie("access_cookie")

      assert "full.token.here" == Utils.get_bearer_token(conn)
      assert :cookie_only == Utils.get_token_transport(conn)
    end

    test "appends cookie signature when cookie starts with dot" do
      conn =
        conn()
        |> put_private(@bearer_token, "header.payload")
        |> put_private(@token_transport, :bearer)
        |> put_req_cookie("c", ".signature")
        |> fetch_cookies()
        |> get_token_from_cookie("c")

      assert "header.payload.signature" == Utils.get_bearer_token(conn)
      assert :cookie == Utils.get_token_transport(conn)
    end

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

    test "ignores cookie when bearer token present but doesn't end with dot and cookie doesn't start with dot" do
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

  describe "get_token_from_auth_header/2" do
    test "extracts bearer token from authorization header" do
      conn =
        conn() |> put_req_header("authorization", "Bearer aaa") |> get_token_from_auth_header([])

      assert {"aaa", :bearer} == {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}

      conn =
        conn() |> put_req_header("authorization", "Bearer: aaa") |> get_token_from_auth_header([])

      assert {"aaa", :bearer} == {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
    end

    test "returns nil when auth header is missing" do
      conn = conn() |> get_token_from_auth_header([])
      assert {nil, nil} == {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
    end

    test "returns nil when auth header format is incorrect" do
      conn = conn() |> put_req_header("authorization", "boom") |> get_token_from_auth_header([])
      assert {nil, nil} == {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}

      conn =
        conn() |> put_req_header("authorization", "Bearer ") |> get_token_from_auth_header([])

      assert {nil, nil} == {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
    end
  end

  describe "verify_token_signature/2" do
    test "verifies valid token signature" do
      token = sign(%{"msg" => "hurray!"})
      conn = conn() |> set_token(token) |> verify_token_signature(@config)
      assert %{"msg" => "hurray!"} = Internal.get_private(conn, @bearer_token_payload)
    end

    test "rejects invalid token signature" do
      token = sign(%{"msg" => "hurray!"})
      conn = conn() |> set_token(token <> "boom") |> verify_token_signature(@config)
      assert nil == Internal.get_private(conn, @bearer_token_payload)
      assert "bearer token signature invalid" == Utils.get_auth_error(conn)
    end

    test "returns error when bearer token not found" do
      conn = conn() |> verify_token_signature(@config)
      assert "bearer token not found" == Utils.get_auth_error(conn)
    end
  end

  describe "verify_token_nbf_claim/2" do
    test "accepts token with valid nbf claim" do
      conn = conn() |> set_token_payload(%{"nbf" => Internal.now()})
      assert ^conn = conn |> verify_token_nbf_claim([])
    end

    test "allows some clock drift" do
      conn = conn() |> set_token_payload(%{"nbf" => Internal.now() + 3})
      assert ^conn = conn |> verify_token_nbf_claim([])
    end

    test "rejects token not yet valid" do
      conn = conn() |> set_token_payload(%{"nbf" => Internal.now() + 6})

      assert "bearer token not yet valid" ==
               conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
    end

    test "requires nbf claim to be present" do
      conn = conn() |> set_token_payload(%{})

      assert "bearer token claim nbf not found" ==
               conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
    end
  end

  describe "verify_token_exp_claim/2" do
    test "accepts token with valid exp claim" do
      conn = conn() |> set_token_payload(%{"exp" => Internal.now()})
      assert ^conn = conn |> verify_token_exp_claim([])
    end

    test "allows some clock drift" do
      conn = conn() |> set_token_payload(%{"exp" => Internal.now() - 3})
      assert ^conn = conn |> verify_token_exp_claim([])
    end

    test "rejects expired token" do
      conn = conn() |> set_token_payload(%{"exp" => Internal.now() - 6})

      assert "bearer token expired" ==
               conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
    end

    test "requires exp claim to be present" do
      conn = conn() |> set_token_payload(%{})

      assert "bearer token claim exp not found" ==
               conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
    end
  end

  describe "verify_token_claim_in/2" do
    test "accepts token with claim in expected values" do
      conn = conn() |> set_token_payload(%{"type" => "access"})
      assert ^conn = conn |> verify_token_claim_in({"type", ~w(access)})
    end

    test "requires claim to be present" do
      conn = conn() |> set_token_payload(%{})

      assert "bearer token claim type not found" ==
               conn |> verify_token_claim_in({"type", ~w(access)}) |> Utils.get_auth_error()
    end
  end

  describe "verify_token_claim_equals/2" do
    test "accepts token with claim equal to expected value" do
      conn = conn() |> set_token_payload(%{"type" => "access"})
      assert ^conn = conn |> verify_token_claim_equals({"type", "access"})
    end

    test "requires claim to be present" do
      conn = conn() |> set_token_payload(%{})

      assert "bearer token claim type not found" ==
               conn |> verify_token_claim_equals({"type", "access"}) |> Utils.get_auth_error()
    end
  end

  describe "verify_no_auth_error/2" do
    test "passes through conn when no auth error present" do
      conn = conn()
      assert ^conn = verify_no_auth_error(conn, fn _conn, _error -> "BOOM" end)
    end

    test "calls error handler when auth error is present" do
      conn = conn() |> set_auth_error("oops!")
      conn = verify_no_auth_error(conn, &(&1 |> send_resp(401, &2) |> halt()))
      assert conn.halted == true
      assert conn.resp_body == "oops!"
    end
  end

  describe "load_session/2" do
    test "fetches session from session store" do
      SessionStore.upsert(test_session(refresh_expires_at: 999_999_999_999_999), @config)
      conn = conn() |> set_token_payload(%{"sid" => "a", "sub" => 1, "styp" => "full"})
      assert %Session{} = conn |> load_session(@config) |> Utils.get_session()
    end

    test "requires token payload to contain sub, sid and styp claims" do
      conn = conn() |> set_token_payload(1)

      assert "bearer token claim sub, sid or styp not found" ==
               conn |> load_session(@config) |> Utils.get_auth_error()
    end

    test "returns error when session not found" do
      conn = conn() |> set_token_payload(%{"sid" => "a", "sub" => 1, "styp" => "full"})
      assert "session not found" == conn |> load_session(@config) |> Utils.get_auth_error()
    end
  end

  describe "verify_session_payload/2" do
    test "accepts valid session" do
      conn = conn() |> set_session(%{the: "session"})
      assert ^conn = conn |> verify_session_payload(fn conn, %{the: "session"} -> conn end)
    end
  end

  describe "verify_token_payload/2" do
    test "accepts valid token payload" do
      conn = conn() |> set_token_payload(%{})
      assert ^conn = conn |> verify_token_payload(fn conn, _pl -> conn end)
    end
  end

  describe "verify_token_ordset_claim_contains/2" do
    test "requires claim to be present" do
      conn = conn() |> set_token_payload(%{})

      assert "bearer token claim scope not found" ==
               conn
               |> verify_token_ordset_claim_contains({"scope", ~w(a b c)})
               |> get_auth_error()
    end
  end

  describe "verify_token_claim/2" do
    test "passes with successful verification" do
      refute conn()
             |> set_token_payload(%{"scope" => "read,write"})
             |> verify_token_claim({"scope", &verify_read_scope/2})
             |> Utils.get_auth_error()
    end

    test "claim must be present" do
      assert "bearer token claim scope not found" ==
               conn()
               |> set_token_payload(%{})
               |> verify_token_claim({"scope", &verify_read_scope/2})
               |> Utils.get_auth_error()
    end
  end

  describe "verify_token_fresh/2" do
    test "allows some clock drift" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now, prev_tokens_fresh_from: now - 10})
        |> set_token_payload(%{"iat" => now - 11})

      refute conn |> verify_token_fresh(5) |> Utils.get_auth_error()
    end

    test "accepts tokens from current generation when within cycle TTL" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 3, prev_tokens_fresh_from: now - 10})
        |> set_token_payload(%{"iat" => now})

      refute conn |> verify_token_fresh(5) |> Utils.get_auth_error()
    end

    test "accepts tokens from previous generation when current gen is within cycle TTL" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 3, prev_tokens_fresh_from: now - 10})

      # younger-than-previous-gen-plus-clock-drift token is valid
      refute conn
             |> set_token_payload(%{"iat" => now - 15})
             |> verify_token_fresh(5)
             |> Utils.get_auth_error()
    end

    test "rejects tokens older than previous generation plus clock drift when current gen is within cycle TTL" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 3, prev_tokens_fresh_from: now - 10})

      # older-than-previous-gen-plus-clock-drift token is invalid
      assert "token stale" ==
               conn
               |> set_token_payload(%{"iat" => now - 16})
               |> verify_token_fresh(5)
               |> Utils.get_auth_error()
    end

    test "does not cycle generation when current gen is within cycle TTL" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 3, prev_tokens_fresh_from: now - 10})
        |> set_token_payload(%{"iat" => now})

      refute conn |> verify_token_fresh(5) |> Internal.get_private(@cycle_token_generation)
    end

    test "accepts current generation tokens when current gen is too old" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 10, prev_tokens_fresh_from: now - 20})
        |> set_token_payload(%{"iat" => now})

      refute conn |> verify_token_fresh(5) |> Utils.get_auth_error()
    end

    test "accepts tokens younger than current gen plus clock drift when current gen is too old" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 10, prev_tokens_fresh_from: now - 20})

      refute conn
             |> set_token_payload(%{"iat" => now - 15})
             |> verify_token_fresh(5)
             |> Utils.get_auth_error()
    end

    test "rejects tokens older than current gen plus clock drift when current gen is too old" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 10, prev_tokens_fresh_from: now - 20})

      assert "token stale" ==
               conn
               |> set_token_payload(%{"iat" => now - 16})
               |> verify_token_fresh(5)
               |> Utils.get_auth_error()
    end

    test "cycles generation when current gen is too old" do
      now = Internal.now()

      conn =
        conn()
        |> set_session(%{tokens_fresh_from: now - 10, prev_tokens_fresh_from: now - 20})
        |> set_token_payload(%{"iat" => now})

      assert conn |> verify_token_fresh(5) |> Internal.get_private(@cycle_token_generation)
    end

    test "requires iat claim to be present" do
      conn =
        conn()
        |> set_session(%{tokens_fresh_from: 0, prev_tokens_fresh_from: 0})
        |> set_token_payload(%{})

      assert "bearer token claim iat not found" ==
               conn |> verify_token_fresh(5) |> Utils.get_auth_error()
    end
  end

  doctest TokenPlugs
end
