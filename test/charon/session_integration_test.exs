defmodule Charon.SessionIntegrationTest do
  use ExUnit.Case
  use Charon.Constants
  alias Charon.TestRedix
  import Charon.TestUtils
  import Plug.Conn
  alias Charon.TestPipeline
  alias Charon.SessionPlugs
  alias Charon.Utils
  import Charon.Internal

  @moduletag :capture_log
  @config TestPipeline.config()

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  def create_session(uid, token_sig_trans, opts \\ []) do
    conn()
    |> Utils.set_user_id(uid)
    |> Utils.set_token_signature_transport(token_sig_trans)
    |> SessionPlugs.upsert_session(@config, opts)
    |> then(fn conn ->
      tokens = Utils.get_tokens(conn)
      session = Utils.get_session(conn)
      cookies = conn.resp_cookies |> Map.new(fn {k, %{value: v}} -> {k, v} end)
      {tokens, cookies, session}
    end)
  end

  describe "pipeline" do
    test "successfully validates a SessionPlugs token" do
      {tokens, cookies, session} = create_session(426, :cookie)
      %{id: sid, refresh_token_id: rtid} = session

      conn =
        conn()
        |> put_req_header("authorization", "Bearer #{tokens.refresh_token}")
        |> then(&%{&1 | cookies: cookies})
        |> TestPipeline.call([])

      assert nil == Utils.get_auth_error(conn)

      assert %{
               # renamed from user_id
               current_user_id: 426,
               session: %Charon.Models.Session{
                 created_at: _,
                 expires_at: _,
                 extra_payload: %{},
                 id: ^sid,
                 refresh_token_id: ^rtid,
                 refreshed_at: _,
                 user_id: 426
               },
               session_id: ^sid,
               token_payload: %{
                 "exp" => _,
                 "iat" => _,
                 "iss" => "my_test_app",
                 "jti" => ^rtid,
                 "nbf" => _,
                 "sid" => ^sid,
                 "sub" => 426,
                 "type" => "refresh"
               }
             } = conn.assigns
    end

    test "rejects stale refresh token" do
      {tokens, cookies, _session} = create_session(1, :cookie)

      conn()
      |> put_req_header("authorization", "Bearer #{tokens.refresh_token}")
      |> then(&%{&1 | cookies: cookies})
      |> TestPipeline.call([])
      # refresh!
      |> SessionPlugs.upsert_session(@config)

      conn =
        conn()
        |> put_req_header("authorization", "Bearer #{tokens.refresh_token}")
        |> then(&%{&1 | cookies: cookies})
        |> TestPipeline.call([])

      assert "refresh token stale" == Utils.get_auth_error(conn)
    end

    test "rejects wrong claims" do
      %{
        %{hi: "boom"} => "claim nbf not found",
        %{nbf: now() + 10} => "bearer token not yet valid",
        %{nbf: now(), exp: now() - 10} => "bearer token expired",
        %{nbf: now(), exp: now()} => "claim type not found",
        %{nbf: now(), exp: now(), type: "bearer"} => "bearer token claim type invalid",
        %{nbf: now(), exp: now(), type: "refresh"} => "claim sub or sid not found",
        %{nbf: now(), exp: now(), type: "refresh", sub: 1, sid: "a"} => "session not found"
      }
      |> Enum.each(fn {payload, exp_error} ->
        {:ok, token} = Charon.TokenFactory.SymmetricJwt.sign(payload, @config)

        conn =
          conn()
          |> put_req_header("authorization", "Bearer #{token}")
          |> TestPipeline.call([])

        assert exp_error == Utils.get_auth_error(conn)
        assert conn.halted
      end)
    end
  end
end
