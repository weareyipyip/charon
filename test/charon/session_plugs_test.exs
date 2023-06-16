defmodule Charon.SessionPlugsTest do
  use ExUnit.Case
  @moduletag :capture_log
  use Charon.Internal.Constants

  alias Charon.SessionPlugs.{
    SessionStorageError,
    SessionUpdateConflictError,
    InsecureTokenTransportError
  }

  alias Plug.Conn
  alias Charon.{Utils, SessionStore}
  alias Charon.Models.{Session, Tokens}
  import Charon.{TestUtils, Internal}
  import Mock

  @config Charon.TestConfig.get()

  @sid "a"
  @uid 426
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: 9_999_999_999_999_999)

  setup do
    start_supervised!(Charon.SessionStore.LocalStore)
    :ok
  end

  import Charon.SessionPlugs

  doctest Charon.SessionPlugs

  describe "delete_session/2" do
    test "should drop session if present" do
      SessionStore.upsert(@user_session, @config)

      conn()
      |> Conn.put_private(@bearer_token_payload, %{"sub" => @uid, "sid" => @sid, "styp" => "full"})
      |> delete_session(@config)

      assert [] == SessionStore.get_all(@uid, :full, @config)
    end
  end

  describe "upsert_session/3" do
    test "should allow sessions with infinite lifespan" do
      conn =
        conn()
        |> upsert_session(%{@config | session_ttl: :infinite},
          user_id: @uid,
          token_transport: :bearer
        )

      session = Utils.get_session(conn)
      assert session.expires_at == :infinite
    end

    test "should not create tokens that outlive the session" do
      tokens =
        conn()
        |> upsert_session(
          %{@config | session_ttl: 10, access_token_ttl: 120, refresh_token_ttl: 120},
          user_id: @uid,
          token_transport: :bearer
        )
        |> Utils.get_tokens()

      assert_in_delta tokens.access_token_exp, now() + 10, 3
      assert_in_delta tokens.refresh_token_exp, now() + 10, 3
    end

    test "should not create tokens that outlive an existing session" do
      session = %{@user_session | expires_at: now() + 10}
      SessionStore.upsert(session, @config)

      tokens =
        conn()
        |> Utils.set_session(%{session | lock_version: session.lock_version + 1})
        |> upsert_session(
          %{@config | session_ttl: 120, access_token_ttl: 120, refresh_token_ttl: 120},
          token_transport: :bearer
        )
        |> Utils.get_tokens()

      assert_in_delta tokens.access_token_exp, now() + 10, 3
      assert_in_delta tokens.refresh_token_exp, now() + 10, 3
    end

    test "should not create cookies that outlive the session" do
      cookies =
        conn()
        |> upsert_session(
          %{@config | session_ttl: 10, access_token_ttl: 120, refresh_token_ttl: 120},
          user_id: @uid,
          token_transport: :cookie
        )
        |> Map.get(:resp_cookies)

      assert_in_delta 10, get_in(cookies, [@config.access_cookie_name, :max_age]), 2
      assert_in_delta 10, get_in(cookies, [@config.refresh_cookie_name, :max_age]), 2
    end

    test "should raise SessionStorageError on sessionstore failure" do
      with_mock SessionStore, upsert: fn _, _ -> {:error, "boom"} end do
        assert_raise SessionStorageError, fn ->
          conn() |> upsert_session(@config, user_id: @uid, token_transport: :bearer)
        end
      end
    end

    test "should raise SessionUpdateConflictError on sessionstore update conflict error" do
      with_mock SessionStore, upsert: fn _, _ -> {:error, :conflict} end do
        assert_raise SessionUpdateConflictError, fn ->
          conn() |> upsert_session(@config, user_id: @uid, token_transport: :bearer)
        end
      end
    end

    test "token transport can't be changed on update" do
      conn =
        conn()
        |> Utils.set_session(@user_session)
        |> put_private(%{@token_transport => :bearer})
        |> upsert_session(@config, token_transport: :cookie)

      assert %{} == conn.resp_cookies
    end

    @enforce_cookie_config %{@config | enforce_cookie_transport: true}

    test "cookie token transport is enforced for browser clients when config enforce_cookie_transport is set" do
      # config option not enabled
      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@config, token_transport: :bearer, user_id: 1)

      assert_raise InsecureTokenTransportError, fn ->
        conn()
        |> Conn.put_req_header("sec-fetch-mode", "boom")
        |> upsert_session(@enforce_cookie_config, token_transport: :bearer, user_id: 1)
      end
    end

    test "cookie transports are allowed when config enforce_cookie_transport is set" do
      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@enforce_cookie_config, token_transport: :cookie, user_id: 1)

      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@enforce_cookie_config, token_transport: :cookie_only, user_id: 1)
    end

    test "bearer transport is allowed when config enforce_cookie_transport is set but not a browser" do
      upsert_session(conn(), @enforce_cookie_config, token_transport: :bearer, user_id: 1)
    end
  end
end
