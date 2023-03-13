defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore
  import Charon.{TestUtils, Internal}
  import Charon.Internal.Crypto
  alias Charon.{TestConfig}
  alias RedisStore.{RedisClient, ConnectionPool}
  import RedisClient, only: [command: 1]

  @ttl 10
  @now now()
  @exp @now + @ttl
  @exp_str to_string(@exp)
  @config %{TestConfig.get() | session_ttl: :infinite, refresh_token_ttl: @ttl}
  @sid "a"
  @uid 426
  @user_session test_session(
                  id: @sid,
                  user_id: @uid,
                  refresh_expires_at: @exp,
                  refreshed_at: @now
                )
  @key session_key(@sid, @uid)
  @set_key user_sessions_key(@uid)

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({ConnectionPool, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  defp serialize(session), do: session |> :erlang.term_to_binary()
  defp sign(binary), do: sign_hmac(binary, RedisStore.default_signing_key(@config))
  defp get(key), do: command(["GET", key]) |> to_result()
  defp list_set_values(key), do: command(["ZRANGE", key, 0, -1, "WITHSCORES"]) |> to_result()
  defp to_result({:ok, result}), do: result
  defp get_exp(key), do: command(["EXPIRETIME", key]) |> to_result()
  defp set_exp(key, exp), do: 1 = command(["EXPIREAT", key, exp]) |> to_result()
  defp add_to_set(set_k, score, v), do: 1 = command(["ZADD", set_k, score, v]) |> to_result()
  defp insert(key, value), do: "OK" = command(["SET", key, value]) |> to_result()

  defp insert(session = %{id: sid, user_id: uid, type: type}) do
    insert(session_key(sid, uid, type), session |> serialize() |> sign())
  end

  describe "get/4" do
    test "returns nil if not found (or expired)" do
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns nil if other type" do
      insert(%{@user_session | type: :oauth2})
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns deserialized session" do
      insert(@user_session)
      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "ignores unsigned session" do
      insert(@key, serialize(@user_session))

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end

    test "ignores signed session with invalid signature" do
      invalid = "signed." <> :crypto.strong_rand_bytes(32) <> "." <> serialize(@user_session)
      insert(@key, invalid)

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end
  end

  describe "upsert/3" do
    test "stores session and adds key to user's set of sessions" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @user_session |> serialize() |> sign() == get(@key)
      assert [@key, _] = list_set_values(user_sessions_key(@uid))
    end

    test "sets ttl / exp score" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @exp = get_exp(@key)
      assert [@key, @exp_str] = list_set_values(@set_key)
      assert @exp = get_exp(@set_key)
    end

    test "separates by type" do
      other_type = %{@user_session | type: :oauth2}
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert :ok = RedisStore.upsert(other_type, @config)
      assert session = get(@key)
      assert oauth2_session = get(session_key(@sid, @uid, :oauth2))
      assert oauth2_session != session

      assert [@key, @exp_str] == list_set_values(@set_key)

      assert [session_key(@sid, @uid, :oauth2), @exp_str] ==
               list_set_values(user_sessions_key(@uid, :oauth2))
    end

    test "updates existing session, ttl, exp" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @exp = get_exp(@key)

      new_exp = @exp + 10

      assert :ok =
               @user_session
               |> Map.merge(%{extra_payload: %{new: "key"}, refresh_expires_at: new_exp})
               |> RedisStore.upsert(@config)

      assert "signed." <> <<_::256>> <> "." <> new_session = get(@key)

      assert ^new_exp = get_exp(@key)
      assert [@key, to_string(new_exp)] == list_set_values(@set_key)

      assert %{extra_payload: %{new: "key"}} = new_session |> :erlang.binary_to_term()
    end

    test "prunes expired sessions" do
      # unexpired, present
      add_to_set(@set_key, @exp, "a")
      # expired, somehow present
      add_to_set(@set_key, 0, "c")

      assert :ok = RedisStore.upsert(@user_session, @config)

      keys = list_set_values(@set_key)
      assert @key in keys
      assert "a" in keys
      assert "c" not in keys
    end

    test "updates user's sessions set ttl" do
      add_to_set(@set_key, @exp, "a")
      set_exp(@set_key, @exp)

      assert @exp == get_exp(@set_key)

      new_exp = @exp + 10
      :ok = RedisStore.upsert(%{@user_session | refresh_expires_at: new_exp}, @config)

      assert new_exp == get_exp(@set_key)
    end

    test "prunes expired sessions on upsert of session with reduced refresh exp" do
      # unexpired, present
      add_to_set(@set_key, @exp, "a")
      # expired, somehow present
      add_to_set(@set_key, 0, "c")

      assert :ok = RedisStore.upsert(%{@user_session | expires_at: @exp}, @config)

      keys = list_set_values(@set_key)
      assert @key in keys
      assert "a" in keys
      assert "c" not in keys
    end

    test "user's session set ttl correct after reduced but highest refresh exp session upsert" do
      add_to_set(@set_key, @exp, "a")
      set_exp(@set_key, @exp)

      new_exp = @exp + 10

      :ok =
        %{@user_session | expires_at: new_exp, refresh_expires_at: new_exp}
        |> RedisStore.upsert(@config)

      assert new_exp == get_exp(@set_key)
    end

    test "user's session set ttl correct after reduced and NOT highest refresh exp session upsert" do
      higher_exp = @exp + 10
      add_to_set(@set_key, higher_exp, "a")
      set_exp(@set_key, higher_exp)

      assert :ok =
               %{@user_session | expires_at: @exp, refresh_expires_at: @exp}
               |> RedisStore.upsert(@config)

      assert higher_exp == get_exp(@set_key)
    end

    test "user's session set ttl correct after reduced first-for-user session upsert" do
      assert :ok =
               %{@user_session | expires_at: @exp, refresh_expires_at: @exp}
               |> RedisStore.upsert(@config)

      assert @exp == get_exp(@set_key)
    end

    test "can handle negative session ttl" do
      :ok =
        @user_session
        |> Map.put(:refresh_expires_at, @exp - 500)
        |> RedisStore.upsert(@config)

      refute get(@key)
      refute get(@set_key)
    end
  end

  describe "delete/4" do
    test "returns ok when not found" do
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
    end

    test "deletes session" do
      insert(@user_session)
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      refute get(@key)
    end

    test "also drops the session key in the user's session set" do
      add_to_set(@set_key, @exp, "a")
      add_to_set(@set_key, @exp, @key)
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert ["a", @exp_str] == list_set_values(@set_key)
    end

    test "prunes expired sessions from user set" do
      # unexpired, present
      add_to_set(@set_key, @exp, @key)
      # expired, somehow present
      add_to_set(@set_key, 0, "c")

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      keys = list_set_values(@set_key)
      refute @key in keys
      assert "c" not in keys
    end

    test "user's session set ttl correct if deleted session was highest exp session" do
      add_to_set(@set_key, @exp, "a")
      add_to_set(@set_key, @exp + 5, @key)
      set_exp(@set_key, @exp + 5)

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      # exp reduced to next-in-line highest exp session
      assert @exp == get_exp(@set_key)
    end

    test "user's session set ttl correct(ed) if deleted session not found" do
      add_to_set(@set_key, @exp, "a")
      # the set should never have this value, which doesn't match the exp of "a"
      set_exp(@set_key, @exp + 5)

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      # exp reduced to next-in-line highest exp session
      assert @exp == get_exp(@set_key)
    end

    test "user's session set ttl correct if deleted session was NOT highest exp session" do
      add_to_set(@set_key, @exp + 5, "a")
      add_to_set(@set_key, @exp, @key)
      set_exp(@set_key, @exp + 5)

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      # set exp is unchanged
      assert @exp + 5 == get_exp(@set_key)
    end

    test "user's session set removed if deleted session was last session" do
      add_to_set(@set_key, @exp, @key)
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      refute get(@set_key)
    end
  end

  describe "get_all/3" do
    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      add_to_set(@set_key, @exp, "a")
      insert("a", %{@user_session | id: "a"} |> serialize() |> sign())
      # unexpired, missing
      add_to_set(@set_key, @exp, "b")
      # expired, somehow present
      add_to_set(@set_key, 0, "c")
      insert("c", %{@user_session | id: "c"} |> serialize() |> sign())
      # expired and missing as it should be
      add_to_set(@set_key, 0, "d")
      # another user's session
      add_to_set(user_sessions_key(@uid + 1), @exp, "e")
      insert("e", %{@user_session | id: "e", user_id: @uid + 1} |> serialize() |> sign())
      # unexpired, present, other type
      add_to_set(user_sessions_key(@uid, :oauth2), @exp, "f")
      insert("f", %{@user_session | id: "f", type: :oauth2} |> serialize() |> sign())

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end
  end

  describe "delete_all/3" do
    test "removes all sessions of requested type and the user's session set" do
      # unexpired, present
      add_to_set(@set_key, @exp, "a")
      insert("a", %{@user_session | id: "a"} |> serialize() |> sign())
      # unexpired, missing
      add_to_set(@set_key, @exp, "b")
      # expired, somehow present
      add_to_set(@set_key, 0, "c")
      insert("c", %{@user_session | id: "c"} |> serialize() |> sign())
      # expired and missing as it should be
      add_to_set(@set_key, 0, "d")
      # another user's session
      other_users_set_key = user_sessions_key(@uid + 1)
      add_to_set(other_users_set_key, @exp, "e")
      insert("e", %{@user_session | id: "e", user_id: @uid + 1} |> serialize() |> sign())
      # unexpired, present, other type
      oauth2_set_key = user_sessions_key(@uid, :oauth2)
      add_to_set(oauth2_set_key, @exp, "f")
      insert("f", %{@user_session | id: "f", type: :oauth2} |> serialize() |> sign())

      assert :ok == RedisStore.delete_all(@uid, :full, @config)
      assert {:ok, keys} = command(~w(KEYS *))

      assert [oauth2_set_key, other_users_set_key, "e", "f"] == Enum.sort(keys)
    end
  end
end
