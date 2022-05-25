defmodule Charon.Sessions.SessionStore.RedisStoreTest do
  use ExUnit.Case, async: true
  alias Charon.Sessions.SessionStore.RedisStore

  @prefix "sess_"
  @config %{custom: %{charon_redis_store: %{redix_module: __MODULE__, key_prefix: @prefix}}}
  @sid "a"
  @uid 1
  @session %{id: @sid, user_id: @uid}
  @serialized :erlang.term_to_binary(@session)
  @session_key [@prefix, ".s.", @uid, ?., @sid] |> IO.iodata_to_binary()
  @user_sessions_key [@prefix, ".u.", @uid] |> IO.iodata_to_binary()
  @ttl 10

  def command(command), do: Redix.command(:redix, command)
  def pipeline(commands), do: Redix.pipeline(:redix, commands)
  defp now(), do: System.system_time(:second)

  setup_all do
    start_supervised!({Redix, name: :redix, host: System.get_env("REDIS_HOSTNAME", "localhost")})
    :ok
  end

  setup do
    command(~w(FLUSHDB))
    :ok
  end

  describe "get/3" do
    test "returns nil if not found (or expired)" do
      assert nil == RedisStore.get(@sid, @uid, @config)
    end

    test "returns deserialized session" do
      command(["SET", @session_key, @serialized])
      assert @session == RedisStore.get(@sid, @uid, @config)
    end
  end

  describe "upsert/3" do
    test "stores session and adds key to user's set of sessions" do
      assert :ok = RedisStore.upsert(@session, @ttl, @config)
      assert {:ok, @serialized} == command(["get", @session_key])
      assert {:ok, [@session_key]} = command(["ZRANGE", @user_sessions_key, 0, -1])
    end

    test "sets ttl / exp score" do
      now = System.system_time(:second)
      assert :ok = RedisStore.upsert(@session, @ttl, @config)
      assert {:ok, ttl} = command(["TTL", @session_key])
      assert_in_delta ttl, @ttl, 3
      assert {:ok, [_, exp]} = command(["ZRANGE", @user_sessions_key, 0, -1, "WITHSCORES"])
      assert_in_delta String.to_integer(exp), now + @ttl, 3
    end

    test "updates existing session, ttl, exp" do
      assert :ok = RedisStore.upsert(@session, @ttl, @config)
      assert {:ok, [_, exp]} = command(["ZRANGE", @user_sessions_key, 0, -1, "WITHSCORES"])

      Process.sleep(1001)

      assert :ok = RedisStore.upsert(Map.put(@session, :new, "key"), @ttl, @config)
      assert {:ok, new_session} = command(["GET", @session_key])
      assert {:ok, new_ttl} = command(["TTL", @session_key])
      assert {:ok, [_, new_exp]} = command(["ZRANGE", @user_sessions_key, 0, -1, "WITHSCORES"])
      assert %{new: "key"} = new_session |> :erlang.binary_to_term()
      # ttl should be reset
      assert_in_delta new_ttl, @ttl, 1
      assert new_exp != exp
    end
  end

  describe "delete/2" do
    test "returns ok when not found" do
      assert :ok = RedisStore.delete(@sid, @uid, @config)
    end

    test "deletes session" do
      command(["SET", @session_key, @serialized])
      assert :ok = RedisStore.delete(@sid, @uid, @config)
      assert {:ok, nil} = command(["GET", @session_key])
    end

    test "leaves the session key in the user's session set alone" do
      command(["ZADD", @user_sessions_key, now() + @ttl, @session_key])
      assert :ok = RedisStore.delete(@sid, @uid, @config)
      assert {:ok, [@session_key]} = command(["ZRANGE", @user_sessions_key, 0, -1])
    end
  end

  describe "get_all/2" do
    test "returns the user's unexpired, deserialized sessions" do
      # unexpired, present
      command(["ZADD", @user_sessions_key, now() + @ttl, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", @user_sessions_key, now() + @ttl, "b"])
      # expired, somehow present
      command(["ZADD", @user_sessions_key, 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", @user_sessions_key, 0, "d"])
      # another user's session
      command(["ZADD", "user2", now() + @ttl, "e"])
      command(["SET", "e", @serialized])

      assert [@session] == RedisStore.get_all(@uid, @config)
    end
  end

  describe "delete_all/2" do
    test "removes all sessions and the user's session set" do
      # unexpired, present
      command(["ZADD", @user_sessions_key, now() + @ttl, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", @user_sessions_key, now() + @ttl, "b"])
      # expired, somehow present
      command(["ZADD", @user_sessions_key, 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", @user_sessions_key, 0, "d"])
      # another user's session
      command(["ZADD", "user2", now() + @ttl, "e"])
      command(["SET", "e", "session_e"])

      assert :ok == RedisStore.delete_all(@uid, @config)
      assert {:ok, keys} = command(~w(KEYS *))
      assert ["e", "user2"] = Enum.sort(keys)
    end
  end

  describe "cleanup/1" do
    test "removes expired keys from user session sets" do
      # unexpired
      command(["ZADD", @user_sessions_key, now() + @ttl, "a"])
      # expired and missing as it should be
      command(["ZADD", @user_sessions_key, 0, "b"])

      assert :ok == RedisStore.cleanup(@config)
      assert {:ok, ["a"]} = command(["ZRANGE", @user_sessions_key, 0, -1])
    end
  end
end
