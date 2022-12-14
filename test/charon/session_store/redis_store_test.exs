defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore
  alias Charon.Models.Session
  import Charon.{TestUtils, Internal}
  alias Charon.TestRedix
  import TestRedix, only: [command: 1]

  @ttl 10
  @config %{
    session_ttl: :infinite,
    refresh_token_ttl: @ttl,
    optional_modules: %{RedisStore => RedisStore.Config.from_enum(redix_module: TestRedix)}
  }
  @sid "a"
  @uid 426
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: now() + @ttl)
  @serialized Session.serialize(@user_session)

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  describe "get/3" do
    test "returns nil if not found (or expired)" do
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns nil if other type" do
      command(["SET", session_key(@sid, @uid, :oauth2), @serialized])
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns deserialized session" do
      command(["SET", session_key(@sid, @uid), @serialized])
      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end
  end

  describe "upsert/3" do
    test "stores session and adds key to user's set of sessions" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert {:ok, @serialized} == command(["get", session_key(@sid, @uid)])

      assert {:ok, [session_key(@sid, @uid)]} ==
               command(["ZRANGE", user_sessions_key(@uid), 0, -1])
    end

    test "sets ttl / exp score" do
      now = now()
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert {:ok, ttl} = command(["TTL", session_key(@sid, @uid)])
      assert_in_delta ttl, @ttl, 3
      assert {:ok, [_, exp]} = command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])
      assert_in_delta String.to_integer(exp), now + @ttl, 3
    end

    test "separates by type" do
      other_type = %{@user_session | type: :oauth2}
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert :ok = RedisStore.upsert(other_type, @config)
      assert {:ok, @serialized} == command(["get", session_key(@sid, @uid)])
      assert {:ok, <<_::binary>>} = command(["get", session_key(@sid, @uid, :oauth2)])

      assert {:ok, [session_key(@sid, @uid)]} ==
               command(["ZRANGE", user_sessions_key(@uid), 0, -1])

      assert {:ok, [session_key(@sid, @uid, :oauth2)]} ==
               command(["ZRANGE", user_sessions_key(@uid, :oauth2), 0, -1])
    end

    test "updates existing session, ttl, exp" do
      assert :ok =
               @user_session
               |> Map.put(:refresh_expires_at, now() + @ttl + 5)
               |> RedisStore.upsert(@config)

      assert {:ok, [_, exp]} = command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])

      Process.sleep(1001)

      assert :ok = RedisStore.upsert(Map.put(@user_session, :new, "key"), @config)
      assert {:ok, new_session} = command(["GET", session_key(@sid, @uid)])
      assert {:ok, new_ttl} = command(["TTL", session_key(@sid, @uid)])

      assert {:ok, [_, new_exp]} =
               command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])

      assert %{new: "key"} = new_session |> :erlang.binary_to_term()
      # ttl should be reset
      assert_in_delta new_ttl, @ttl, 1
      assert new_exp != exp
    end
  end

  describe "delete/4" do
    test "returns ok when not found" do
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
    end

    test "deletes session" do
      command(["SET", session_key(@sid, @uid), @serialized])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, nil} = command(["GET", session_key(@sid, @uid)])
    end

    test "leaves the session key in the user's session set alone" do
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, session_key(@sid, @uid)])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, [session_key(@sid, @uid)]} ==
               command(["ZRANGE", user_sessions_key(@uid), 0, -1])
    end
  end

  describe "get_all/3" do
    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", "user2", now() + @ttl, "e"])
      command(["SET", "e", @serialized])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), now() + @ttl, "f"])
      command(["SET", "f", @serialized])

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end
  end

  describe "delete_all/3" do
    test "removes all session of requested type and the user's session set" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", user_sessions_key(@uid + 1), now() + @ttl, "e"])
      command(["SET", "e", "session_e"])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), now() + @ttl, "f"])
      command(["SET", "f", @serialized])

      assert :ok == RedisStore.delete_all(@uid, :full, @config)
      assert {:ok, keys} = command(~w(KEYS *))

      assert [
               user_sessions_key(@uid, :oauth2) |> IO.iodata_to_binary(),
               user_sessions_key(@uid + 1) |> IO.iodata_to_binary(),
               "e",
               "f"
             ] == Enum.sort(keys)
    end
  end

  describe "cleanup/1" do
    test "works with empty db" do
      assert capture_log(fn -> assert :ok == RedisStore.cleanup(@config) end) =~
               "Removed 0 expired session keys."
    end

    test "removes expired keys from user session sets" do
      # unexpired
      command(["ZADD", user_sessions_key(@uid), now() + @ttl, "a"])
      # expired, of other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), 0, "c"])

      for n <- 1..100 do
        # expired and missing as it should be
        command(["ZADD", user_sessions_key(n), 0, "b"])
      end

      assert capture_log(fn ->
               assert :ok == RedisStore.cleanup(@config)
             end) =~ "Removed 101 expired session keys."

      assert {:ok, ["a"]} = command(["ZRANGE", user_sessions_key(@uid), 0, -1])
    end
  end
end
