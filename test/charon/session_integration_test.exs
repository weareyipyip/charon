defmodule Charon.SessionIntegrationTest do
  use ExUnit.Case, async: false
  use Charon.Internal.Constants
  alias Charon.{TestPipeline, SessionPlugs, Utils, Internal, TestUtils, TestHelpers}
  import TestUtils
  import Plug.Conn
  import Internal
  import Mock

  @moduletag :capture_log
  @config Charon.TestConfig.get()

  setup do
    start_supervised!(Charon.SessionStore.LocalStore)
    :ok
  end

  describe "pipeline" do
    test "successfully validates a SessionPlugs token" do
      test_session = TestHelpers.create_session(@config, user_id: 426, token_transport: :cookie)
      %{session: %{id: sid, refresh_token_id: rtid}} = test_session

      conn =
        conn()
        |> TestHelpers.put_token_for(test_session, token: :refresh)
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

    test "rejects stale refresh token depending on token cycle TTL and iat claim" do
      %{tokens: %{refresh_token: r1}} = TestHelpers.create_session(@config, user_id: 1)

      refresher = fn token ->
        conn()
        |> put_req_header("authorization", "Bearer #{token}")
        |> TestPipeline.call([])
        |> case do
          %{private: %{@auth_error => error}} -> error
          conn -> SessionPlugs.upsert_session(conn, @config)
        end
      end

      now = Internal.now()

      # let's wait for the cycle TTL to pass (5s cycle ttl + 5s clock drift allowance)
      {r2, r3} =
        with_mock Internal, [:passthrough], now: fn -> now + 10 end do
          # token r1, now "previous gen" should still be usable, multiple times
          assert %{private: %{@tokens => %{refresh_token: r2}}} = refresher.(r1)
          assert %{private: %{@tokens => %{refresh_token: r3}}} = refresher.(r1)
          assert %{private: %{@tokens => %{refresh_token: _r4}}} = refresher.(r1)
          {r2, r3}
        end

      # "wait" for the cycle TTL to pass again, causing the "previous gen" to become invalid
      with_mock Internal, [:passthrough], now: fn -> now + 20 end do
        # token r1, now discarded, is no longer usable
        assert "token stale" == refresher.(r1)
        # tokens r2 and r3, now "previous gen", are still usable
        assert %{private: %{@tokens => %{refresh_token: r5}}} = refresher.(r2)
        assert %{private: %{@tokens => %{refresh_token: _r6}}} = refresher.(r2)
        assert %{private: %{@tokens => %{refresh_token: _r7}}} = refresher.(r3)
        assert %{private: %{@tokens => %{refresh_token: _r8}}} = refresher.(r3)
        # token r5, "current gen", is usable too
        assert %{private: %{@tokens => %{refresh_token: _r9}}} = refresher.(r5)
      end
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
        %{nbf: now(), exp: now(), type: "refresh", sub: 1, sid: "a", styp: "full"} =>
          "session not found"
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
