defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore
  import Charon.{TestUtils, Internal}
  import Charon.Utils.Crypto
  alias Charon.{TestRedix, TestConfig}
  import TestRedix, only: [command: 1]

  @ttl 10
  @exp now() + @ttl
  @mod_conf RedisStore.Config.from_enum(redix_module: TestRedix)
  @config %{
    TestConfig.get()
    | session_ttl: :infinite,
      refresh_token_ttl: @ttl,
      optional_modules: %{RedisStore => @mod_conf}
  }
  @sid "a"
  @uid 426
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: @exp)
  @serialized :erlang.term_to_binary(@user_session)
  @mac hmac(@serialized, RedisStore.default_signing_key(@config))
  @signed_serialized "signed." <> @mac <> "." <> @serialized

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  describe "get/4" do
    test "returns nil if not found (or expired)" do
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns nil if other type" do
      command(["SET", session_key(@sid, @uid, :oauth2), @signed_serialized])
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns deserialized session" do
      command(["SET", session_key(@sid, @uid), @signed_serialized])
      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "ignores unsigned session" do
      command(["SET", session_key(@sid, @uid), @serialized])

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end

    test "ignores signed session with invalid signature" do
      command([
        "SET",
        session_key(@sid, @uid),
        "signed." <> :crypto.strong_rand_bytes(32) <> "." <> @serialized
      ])

      # even if allow_unsigned? = true, sessions with an invalid signature are ignored
      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end
  end

  describe "upsert/3" do
    test "stores session and adds key to user's set of sessions" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert {:ok, @signed_serialized} == command(["get", session_key(@sid, @uid)])

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
      assert {:ok, @signed_serialized} == command(["get", session_key(@sid, @uid)])
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

      assert {:ok, "signed." <> <<_::256>> <> "." <> new_session} =
               command(["GET", session_key(@sid, @uid)])

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

      assert :ok = RedisStore.upsert(@user_session, @config)

      assert {:ok, keys} = command(["ZRANGE", user_key, 0, -1])
      assert "a" in keys
      assert "c" not in keys
    end

    test "updates user's sessions set ttl" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok = RedisStore.upsert(%{@user_session | refresh_expires_at: @exp + 10}, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 10, 3
    end

    test "prunes expired sessions with reduced refresh exp" do
      user_key = user_sessions_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      # expired, somehow present
      command(["ZADD", user_key, 0, "c"])

      assert :ok = RedisStore.upsert(%{@user_session | expires_at: @exp}, @config)

      assert {:ok, keys} = command(["ZRANGE", user_key, 0, -1])
      assert "a" in keys
      assert "c" not in keys
    end

    test "user's session set ttl correct after reduced but highest refresh exp session upsert" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok =
               %{@user_session | expires_at: @exp + 10, refresh_expires_at: @exp + 10}
               |> RedisStore.upsert(@config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 10, 3
    end

    test "user's session set ttl correct after reduced and NOT highest refresh exp session upsert" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp + 10, "a"])
      command(["EXPIRE", user_key, "#{@ttl + 10}"])

      assert :ok =
               %{@user_session | expires_at: @exp, refresh_expires_at: @exp}
               |> RedisStore.upsert(@config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 10, 3
    end

    test "user's session set ttl correct after reduced first-for-user session upsert" do
      user_key = user_sessions_key(@uid)

      assert :ok =
               %{@user_session | expires_at: @exp, refresh_expires_at: @exp}
               |> RedisStore.upsert(@config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
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
      command(["SET", session_key(@sid, @uid), @signed_serialized])
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
      assert "c" not in keys
    end

    test "user's session set ttl correct if deleted session was highest exp session" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["ZADD", user_key, @exp + 5, _to_delete = session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl + 5}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
    end

    test "user's session set ttl correct if deleted session not found" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
    end

    test "user's session set ttl correct if deleted session was NOT highest exp session" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp + 5, "a"])
      command(["ZADD", user_key, @exp, _to_delete = session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl + 5}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 5, 3
    end

    test "user's session set removed if deleted session was last session" do
      user_key = user_sessions_key(@uid)
      command(["ZADD", user_key, @exp, _to_delete = session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, 0} = command(["EXISTS", user_key])
    end
  end

  describe "get_all/3" do
    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), @exp, "a"])
      command(["SET", "a", @signed_serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @signed_serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", "user2", @exp, "e"])
      command(["SET", "e", @signed_serialized])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), @exp, "f"])
      command(["SET", "f", @signed_serialized])

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end
  end

  describe "delete_all/3" do
    test "removes all sessions of requested type and the user's session set" do
      # unexpired, present
      command(["ZADD", user_sessions_key(@uid), @exp, "a"])
      command(["SET", "a", @signed_serialized])
      # unexpired, missing
      command(["ZADD", user_sessions_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", user_sessions_key(@uid), 0, "c"])
      command(["SET", "c", @signed_serialized])
      # expired and missing as it should be
      command(["ZADD", user_sessions_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", user_sessions_key(@uid + 1), @exp, "e"])
      command(["SET", "e", "session_e"])
      # unexpired, present, other type
      command(["ZADD", user_sessions_key(@uid, :oauth2), @exp, "f"])
      command(["SET", "f", @signed_serialized])

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
