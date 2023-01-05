defmodule Charon.SessionIntegrationTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  alias Charon.{SessionStore, TestRedix, TestPipeline, SessionPlugs, Utils, Internal, TestUtils}
  import TestUtils
  import Plug.Conn
  import Internal

  @moduletag :capture_log
  @config Charon.TestConfig.get()

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
      %{id: sid, refresh_tokens: refresh_tokens} = session

      conn =
        conn()
        |> put_req_header("authorization", "Bearer #{tokens.refresh_token}")
        |> then(&%{&1 | cookies: cookies})
        |> TestPipeline.call([])

      assert nil == Utils.get_auth_error(conn)

      [rtid] = refresh_tokens

      assert %{
               # renamed from user_id
               current_user_id: 426,
               session: %Charon.Models.Session{
                 created_at: _,
                 expires_at: _,
                 extra_payload: %{},
                 id: ^sid,
                 refresh_tokens: ^refresh_tokens,
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

    test "rejects stale refresh token in generations per grace period" do
      {%{refresh_token: r1}, _cookies, session} = create_session(1, :bearer)

      refresher = fn token ->
        conn()
        |> put_req_header("authorization", "Bearer #{token}")
        |> TestPipeline.call([])
        |> case do
          %{private: %{@auth_error => error}} -> error
          conn -> SessionPlugs.upsert_session(conn, @config)
        end
      end

      # "wait" for the grace period to pass, causing the current refresh token(s) to be considered "previous gen"
      retire_token_gen = fn ->
        SessionStore.get(session.id, session.user_id, session.type, @config)
        |> then(fn s -> %{s | refresh_tokens_at: 0} end)
        |> SessionStore.upsert(@config)
      end

      # let's wait
      retire_token_gen.()

      # token r1, now "previous gen" should still be usable, multiple times
      assert %{private: %{@tokens => %{refresh_token: r2}}} = refresher.(r1)
      assert %{private: %{@tokens => %{refresh_token: r3}}} = refresher.(r1)
      assert %{private: %{@tokens => %{refresh_token: _r4}}} = refresher.(r1)

      # "wait" for the grace period to pass again, causing the "previous gen" to be discarded
      retire_token_gen.()

      # token r1, now discarded, is no longer usable
      assert "refresh token stale" == refresher.(r1)
      # tokens r2 and r3, now "previous gen", are still usable
      assert %{private: %{@tokens => %{refresh_token: r5}}} = refresher.(r2)
      assert %{private: %{@tokens => %{refresh_token: _r6}}} = refresher.(r2)
      assert %{private: %{@tokens => %{refresh_token: _r7}}} = refresher.(r3)
      assert %{private: %{@tokens => %{refresh_token: _r8}}} = refresher.(r3)
      # token r5, "current gen", is usable too
      assert %{private: %{@tokens => %{refresh_token: _r9}}} = refresher.(r5)
    end

    test "rejects wrong claims" do
      %{
        %{hi: "boom"} => "bearer token claim nbf not found",
        %{nbf: now() + 10} => "bearer token not yet valid",
        %{nbf: now(), exp: now() - 10} => "bearer token expired",
        %{nbf: now(), exp: now()} => "bearer token claim type not found",
        %{nbf: now(), exp: now(), type: "bearer"} => "bearer token claim type invalid",
        %{nbf: now(), exp: now(), type: "refresh"} =>
          "bearer token claim sub, sid or styp not found",
        # this works because a default claim styp=full is added
        %{nbf: now(), exp: now(), type: "refresh", sub: 1, sid: "a"} => "session not found"
      }
      |> Enum.each(fn {payload, exp_error} ->
        {:ok, token} = Charon.TokenFactory.Jwt.sign(payload, @config)

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
