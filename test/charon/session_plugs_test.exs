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

    test "should instruct browsers to clear signature cookies" do
      cookies =
        conn()
        |> Plug.Test.put_req_cookie(@config.access_cookie_name, "anything")
        |> Plug.Test.put_req_cookie(@config.refresh_cookie_name, "anything")
        |> delete_session(@config)
        |> Conn.fetch_cookies()
        |> Map.get(:cookies)

      assert cookies == %{}
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

    @dont_enforce_cookie_cfg %{@config | enforce_browser_cookies: false}

    test "cookie token transport is enforced for browser clients when config enforce_browser_cookies is set" do
      # config option not enabled
      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@dont_enforce_cookie_cfg, token_transport: :bearer, user_id: 1)

      assert_raise InsecureTokenTransportError, fn ->
        conn()
        |> Conn.put_req_header("sec-fetch-mode", "boom")
        |> upsert_session(@config, token_transport: :bearer, user_id: 1)
      end
    end

    test "cookie transports are allowed when config enforce_browser_cookies is set" do
      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@config, token_transport: :cookie, user_id: 1)

      conn()
      |> Conn.put_req_header("sec-fetch-mode", "boom")
      |> upsert_session(@config, token_transport: :cookie_only, user_id: 1)
    end

    test "bearer transport is allowed when config enforce_browser_cookies is set but not a browser" do
      upsert_session(conn(), @config, token_transport: :bearer, user_id: 1)
    end

    test "should allow use :gen_id config option for session/refresh/access id" do
      conn =
        conn()
        |> upsert_session(
          %{@config | gen_id: fn -> "123" end},
          user_id: @uid,
          token_transport: :bearer
        )

      assert %{id: "123", refresh_token_id: "123"} = Utils.get_session(conn)
      assert %{"jti" => "123"} = Utils.get_tokens(conn).access_token |> peek_payload()
    end

    test "user and signature transport must be set" do
      assert_raise RuntimeError,
                   "Set token transport using upsert_session/3 option :token_transport",
                   fn -> conn() |> upsert_session(@config, user_id: @uid) end

      assert_raise RuntimeError,
                   "Set user id using upsert_session/3 option :user_id",
                   fn -> conn() |> upsert_session(@config, token_transport: :bearer) end
    end

    test "renews session if present in conn, updating only refresh fields" do
      old_session =
        test_session(
          user_id: 43,
          id: "a",
          expires_at: :infinite,
          refresh_expires_at: 0,
          refreshed_at: 0
        )

      conn =
        conn()
        |> Conn.put_private(@session, old_session)
        |> upsert_session(@config, user_id: 1, token_transport: :bearer)

      session = Utils.get_session(conn) |> Map.from_struct()
      old_session = Map.from_struct(old_session)
      # These fields should not change
      assert session.id == old_session.id
      assert session.user_id == old_session.user_id
      assert session.created_at == old_session.created_at
      assert session.expires_at == old_session.expires_at
      # These fields should change
      refute session.refresh_token_id == old_session.refresh_token_id
      refute session.refreshed_at == old_session.refreshed_at
      refute session.refresh_expires_at == old_session.refresh_expires_at
    end

    test "returns token signatures in cookies if token transport is :cookie" do
      conn = upsert_session(conn(), @config, user_id: 1, token_transport: :cookie)
      cookies = conn |> Conn.fetch_cookies() |> Map.get(:cookies)

      # Cookies contain signatures
      assert <<_access_sig::binary>> = Map.get(cookies, @config.access_cookie_name)
      assert <<_refresh_sig::binary>> = Map.get(cookies, @config.refresh_cookie_name)

      # Tokens are partial (only 2 parts: header.payload)
      tokens = Utils.get_tokens(conn)
      assert [_, _] = String.split(tokens.access_token, ".", trim: true)
      assert [_, _] = String.split(tokens.refresh_token, ".", trim: true)

      # Cookie options are set correctly
      cookie_opts = conn.resp_cookies[@config.refresh_cookie_name]
      assert cookie_opts.http_only == true
      assert cookie_opts.same_site == "Strict"
      assert cookie_opts.secure == true
      assert is_integer(cookie_opts.max_age)
    end

    test "returns full tokens in cookies if token transport is :cookie_only" do
      conn = upsert_session(conn(), @config, user_id: 1, token_transport: :cookie_only)
      cookies = conn |> Conn.fetch_cookies() |> Map.get(:cookies)

      # Cookies contain full tokens (3 parts: header.payload.signature)
      assert [_, _, _] =
               cookies |> Map.get(@config.access_cookie_name) |> String.split(".", trim: true)

      assert [_, _, _] =
               cookies |> Map.get(@config.refresh_cookie_name) |> String.split(".", trim: true)

      # Token structs don't contain tokens (they're in cookies only)
      assert %{access_token: nil, refresh_token: nil} = Utils.get_tokens(conn)
    end

    test "tokens get default claims" do
      conn = upsert_session(conn(), @config, user_id: 1, token_transport: :bearer)

      assert %{
               "iss" => "my_test_app",
               "sub" => 1,
               "type" => "access",
               "styp" => "full",
               "exp" => _,
               "iat" => _,
               "nbf" => _,
               "jti" => _,
               "sid" => sid
             } = get_private(conn, @access_token_payload)

      assert %{
               "iss" => "my_test_app",
               "sub" => 1,
               "type" => "refresh",
               "styp" => "full",
               "sid" => ^sid,
               "exp" => _,
               "iat" => _,
               "nbf" => _,
               "jti" => _
             } = get_private(conn, @refresh_token_payload)
    end

    test "allows adding extra claims to tokens" do
      conn =
        upsert_session(
          conn(),
          @config,
          user_id: 1,
          token_transport: :bearer,
          access_claim_overrides: %{"much" => :extra},
          refresh_claim_overrides: %{"really" => true}
        )

      assert %{"much" => :extra} = get_private(conn, @access_token_payload)
      assert %{"really" => true} = get_private(conn, @refresh_token_payload)
    end

    test "allows adding extra payload to session" do
      conn =
        upsert_session(
          conn(),
          @config,
          user_id: 1,
          token_transport: :bearer,
          extra_session_payload: %{what?: "that's right!"}
        )

      assert %Session{extra_payload: %{what?: "that's right!"}} = Utils.get_session(conn)
    end

    test "allows separating sessions by type" do
      conn =
        upsert_session(conn(), @config,
          session_type: :oauth2,
          user_id: 1,
          token_transport: :bearer
        )

      assert %Session{type: :oauth2} = Utils.get_session(conn)
      assert %{"styp" => "oauth2"} = get_private(conn, @access_token_payload)
    end
  end
end
