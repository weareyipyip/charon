defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  alias Charon.SessionStore.RedisStore
  alias Charon.Models.Session
  import Charon.{TestUtils, Internal}
  alias Charon.TestRedix
  import TestRedix, only: [command: 1]

  @ttl 10
  @exp now() + @ttl
  @config %{
    session_ttl: :infinite,
    refresh_token_ttl: @ttl,
    optional_modules: %{RedisStore => RedisStore.Config.from_enum(redix_module: TestRedix)}
  }
  @sid "a"
  @uid 426
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: @exp)
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
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert {:ok, ttl} = command(["TTL", session_key(@sid, @uid)])
      assert_in_delta ttl, @ttl, 3
      assert {:ok, [_, exp]} = command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])
      assert_in_delta String.to_integer(exp), @exp, 3
      assert {:ok, ttl} = command(["TTL", user_sessions_key(@uid)])
      assert_in_delta ttl, @ttl, 3
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
               |> Map.put(:refresh_expires_at, @exp + 5)
               |> RedisStore.upsert(@config)

      assert {:ok, [_, exp]} = command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])
      assert {:ok, ttl} = command(["TTL", session_key(@sid, @uid)])

      assert :ok =
               @user_session
               |> Map.merge(%{extra_payload: %{new: "key"}, refresh_expires_at: @exp + 10})
               |> RedisStore.upsert(@config)

      assert {:ok, new_session} = command(["GET", session_key(@sid, @uid)])
      assert {:ok, new_ttl} = command(["TTL", session_key(@sid, @uid)])

      assert {:ok, [_, new_exp]} =
               command(["ZRANGE", user_sessions_key(@uid), 0, -1, "WITHSCORES"])

      assert %{extra_payload: %{new: "key"}} = new_session |> :erlang.binary_to_term()
      # ttl should be reset
      assert_in_delta new_ttl, ttl, 5
      assert new_exp != exp
    end

    test "prunes expired sessions" do
      user_key = user_sessions_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      # expired, somehow present
      command(["ZADD", user_key, 0, "c"])

      assert :ok =
               @user_session
               |> Map.merge(%{refresh_expires_at: @exp + 10})
               |> RedisStore.upsert(@config)

      assert {:ok, keys} = command(["ZRANGE", user_key, 0, -1])
      assert "a" in keys
      refute "c" in keys
    end

    test "updates user's sessions set ttl" do
      user_key = user_sessions_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      command(["EXPIRE", user_key, "10000"])

      assert :ok =
               @user_session
               |> Map.merge(%{refresh_expires_at: @exp + 10})
               |> RedisStore.upsert(@config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 10, 3
    end

    test "can handle negative session ttl" do
      assert :ok =
               @user_session
               |> Map.put(:refresh_expires_at, now() - 5)
               |> RedisStore.upsert(@config)
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

    test "also drops the session key in the user's session set" do
      command(["ZADD", user_sessions_key(@uid), @exp, session_key(@sid, @uid)])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, []} == command(["ZRANGE", user_sessions_key(@uid), 0, -1])
    end

    test "can handle negative session ttl" do
      command(["ZADD", user_sessions_key(@uid), "3", session_key(@sid, @uid)])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
    end

    test "prunes expired sessions" do
      user_key = user_sessions_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      # expired, somehow present
      command(["ZADD", user_key, 0, "c"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, keys} = command(["ZRANGE", user_key, 0, -1])
      assert "a" in keys
      refute "c" in keys
    end

    test "updates user's sessions set ttl" do
      user_key = user_sessions_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      command(["ZADD", user_key, @exp + 1000, session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "10000"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
    end
  end

  describe "get_all/3" do
    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), @exp, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", "user2", @exp, "e"])
      command(["SET", "e", @serialized])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), @exp, "f"])
      command(["SET", "f", @serialized])

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end
  end

  describe "delete_all/3" do
    test "removes all session of requested type and the user's session set" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), @exp, "a"])
      command(["SET", "a", @serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", user_sessions_key(@uid + 1), @exp, "e"])
      command(["SET", "e", "session_e"])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), @exp, "f"])
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
end
