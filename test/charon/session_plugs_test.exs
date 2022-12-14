defmodule Charon.SessionPlugsTest do
  use ExUnit.Case
  @moduletag :capture_log
  use Charon.Internal.Constants
  alias Plug.Conn
  alias Charon.Utils
  alias Charon.Models.{Session, Tokens}
  import Charon.{TestUtils, Internal}
  alias Charon.TestRedix
  import TestRedix, only: [command: 1]

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            optional_modules: %{
              Charon.TokenFactory.SymmetricJwt => %{get_secret: &__MODULE__.get_secret/0},
              Charon.SessionStore.RedisStore => %{redix_module: TestRedix}
            }
          )

  @sid "a"
  @uid 426
  @user_session test_session(id: @sid, user_id: @uid)
  @serialized Session.serialize(@user_session)

  def get_secret(), do: "supersecret"

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  import Charon.SessionPlugs

  doctest Charon.SessionPlugs

  describe "delete_session/2" do
    test "should drop session if present" do
      command(["SET", session_key(@sid, @uid), @serialized])

      conn()
      |> Conn.put_private(@bearer_token_payload, %{"sub" => @uid, "sid" => @sid})
      |> delete_session(@config)

      assert {:ok, []} = command(~w(KEYS *))
    end
  end

  describe "upsert_session/3" do
    test "should allow sessions with infinite lifespan" do
      conn =
        conn()
        |> Utils.set_token_signature_transport(:bearer)
        |> Utils.set_user_id(@uid)
        |> upsert_session(%{@config | session_ttl: :infinite})

      session = Utils.get_session(conn)
      assert session.expires_at == :infinite
    end

    test "should store sessions with refresh ttl, not session ttl" do
      # if this test fails, unused infinite-ttl sessions would keep accumulating in session stores
      conn()
      |> Utils.set_token_signature_transport(:bearer)
      |> Utils.set_user_id(@uid)
      |> upsert_session(%{@config | session_ttl: :infinite})
      |> Utils.get_session()
      |> Map.get(:id)
      |> then(fn id ->
        assert_in_delta @config.refresh_token_ttl,
                        command(["TTL", session_key(id, @uid)]) |> elem(1),
                        3
      end)
    end

    test "should not create tokens that outlive the session" do
      tokens =
        conn()
        |> Utils.set_token_signature_transport(:bearer)
        |> Utils.set_user_id(@uid)
        |> upsert_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Utils.get_tokens()

      assert_in_delta tokens.access_token_exp, now() + 10, 3
      assert_in_delta tokens.refresh_token_exp, now() + 10, 3
    end

    test "should not create cookies that outlive the session" do
      cookies =
        conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(@uid)
        |> upsert_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Map.get(:resp_cookies)

      assert_in_delta 10, get_in(cookies, [@config.access_cookie_name, :max_age]), 2
      assert_in_delta 10, get_in(cookies, [@config.refresh_cookie_name, :max_age]), 2
    end
  end
end
