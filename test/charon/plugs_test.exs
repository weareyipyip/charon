defmodule Charon.Sessions.SessionPlugsTest do
  use ExUnit.Case
  @moduletag :capture_log
  use Charon.Constants
  alias Plug.Conn
  alias Charon.Utils
  alias Charon.Models.{Session, Tokens}
  import Plug.Test
  import Charon.TestUtils

  @sid "a"
  @uid 1
  @session %{id: @sid, user_id: @uid}
  @serialized :erlang.term_to_binary(@session)

  @config Charon.Config.from_enum(
            session_ttl: 68400,
            refresh_token_ttl: 3600,
            token_issuer: "my_test_app",
            custom: %{
              charon_symmetric_jwt: %{get_secret: &__MODULE__.get_secret/0},
              charon_redis_store: %{redix_module: __MODULE__}
            }
          )

  def command(command), do: Redix.command(:redix, command)
  def pipeline(commands), do: Redix.pipeline(:redix, commands)
  defp now(), do: System.system_time(:second)
  defp conn(), do: conn(:get, "/")
  def get_secret(), do: "supersecret"

  setup_all do
    start_supervised!({Redix, name: :redix, host: System.get_env("REDIS_HOSTNAME", "localhost")})
    :ok
  end

  setup do
    command(~w(FLUSHDB))
    :ok
  end

  import Charon.Sessions.SessionPlugs

  doctest Charon.Sessions.SessionPlugs

  describe "delete_session/2" do
    test "should drop session if present" do
      command(["SET", session_key(@sid, @uid), @serialized])

      conn()
      |> Conn.put_private(@private_user_id_key, @uid)
      |> Conn.put_private(@private_session_id_key, @sid)
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
        |> upsert_session(%{@config | session_ttl: nil})

      session = Utils.get_session(conn)
      assert session.expires_at == nil
    end

    test "should store sessions with refresh ttl, not session ttl" do
      # if this test fails, unused infinite sessions would keep accumulating in session stores
      conn()
      |> Utils.set_token_signature_transport(:bearer)
      |> Utils.set_user_id(@uid)
      |> upsert_session(%{@config | session_ttl: nil})
      |> Utils.get_session()
      |> Map.get(:id)
      |> then(fn id ->
        assert_in_delta 3600, command(["TTL", session_key(id, @uid)]) |> elem(1), 3
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
