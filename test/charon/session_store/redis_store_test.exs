defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore
  import Charon.{TestUtils, Internal, TestHelpers}
  import Charon.Internal.Crypto
  alias Charon.{TestRedix, TestConfig}
  import TestRedix, only: [command: 1]

  @ttl 10
  @now now()
  @exp @now + @ttl
  @exp_str to_string(@exp)
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
  @session_set_key session_set_key(@uid)
  @exp_oset_key exp_oset_key(@uid)

  defp serialize(session), do: session |> :erlang.term_to_binary()
  defp sign(binary), do: sign_hmac(binary, RedisStore.default_signing_key(@config))
  defp list_oset_values(key), do: command(["ZRANGE", key, 0, -1, "WITHSCORES"]) |> to_result()
  defp list_hset_values(key), do: command(["HGETALL", key]) |> to_result()
  defp to_result({:ok, result}), do: result
  defp get_ttl(key), do: command(["TTL", key]) |> to_result()
  defp set_ttl(key, ttl), do: 1 = command(["EXPIRE", key, ttl]) |> to_result()
  defp add_to_oset(set_k, score, v), do: 1 = command(["ZADD", set_k, score, v]) |> to_result()
  defp add_to_hash_set(set_k, k, v), do: 1 = command(["HSET", set_k, k, v]) |> to_result()
  defp add_session_set(k, v), do: add_to_hash_set(@session_set_key, k, v)
  defp get_hash_set(set_k, k), do: command(["HGET", set_k, k]) |> to_result()
  defp get_session_set(k), do: get_hash_set(@session_set_key, k)

  defp insert(session = %{id: sid, user_id: uid, type: type, refresh_expires_at: exp}) do
    serialized_signed = session |> serialize() |> sign()
    add_to_hash_set(session_set_key(uid, type), sid, serialized_signed)
    add_to_oset(exp_oset_key(uid, type), exp, sid)
  end

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
      command(["SET", old_session_key(@sid, @uid, :oauth2), @signed_serialized])
      assert nil == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns deserialized session" do
      command(["SET", old_session_key(@sid, @uid), @signed_serialized])
      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "returns unsigned session if allow_unsigned? = true" do
      command(["SET", old_session_key(@sid, @uid), @serialized])

      assert capture_log(fn ->
               assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Unsigned session a fetched"
    end

    test "ignores unsigned session if allow_unsigned? = false" do
      command(["SET", old_session_key(@sid, @uid), @serialized])

      config = override_opt_mod_conf(@config, RedisStore, allow_unsigned?: false)

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, config)
             end) =~ "Ignored Redis session"
    end

    test "ignores signed session with invalid signature" do
      command([
        "SET",
        old_session_key(@sid, @uid),
        "signed." <> :crypto.strong_rand_bytes(32) <> "." <> @serialized
      ])

      # even if allow_unsigned? = true, sessions with an invalid signature are ignored
      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end

    test "gets session with old key format" do
      command([
        "SET",
        RedisStore.old_session_key(@sid, {to_string(@uid), "full", "charon_"}),
        @signed_serialized
      ])

      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end

    test "gets session with newest storage format" do
      command(["HSET", @session_set_key, @sid, @signed_serialized])
      assert @user_session == RedisStore.get(@sid, @uid, :full, @config)
    end
  end

  describe "upsert/3" do
    test "stores session, lock and exp" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @signed_serialized == get_session_set(@sid)
      assert [@sid, @exp_str] == list_oset_values(@exp_oset_key)
    end

    test "sets session sets ttl / exp score" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @ttl = get_ttl(@exp_oset_key)
      assert @ttl = get_ttl(@session_set_key)
    end

    test "separates by type" do
      other_type = %{@user_session | type: :oauth2}
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert :ok = RedisStore.upsert(other_type, @config)
      assert session = get_session_set(@sid)
      assert oauth2_session = get_hash_set(session_set_key(@uid, :oauth2), @sid)
      assert oauth2_session != session
    end

    test "updates existing session and set expirations" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      set_ttl(@exp_oset_key, 5)
      set_ttl(@session_set_key, 5)

      :ok =
        @user_session |> Map.merge(%{extra_payload: %{new: "key"}}) |> RedisStore.upsert(@config)

      assert "signed." <> <<_::256>> <> "." <> new_session = get_session_set(@sid)

      assert @ttl == get_ttl(@exp_oset_key)
      assert @ttl == get_ttl(@session_set_key)
      assert [@sid, to_string(@exp)] == list_oset_values(@exp_oset_key)

      assert %{extra_payload: %{new: "key"}} = new_session |> :erlang.binary_to_term()
    end

    test "prunes expired sessions" do
      # unexpired, present
      add_to_oset(@exp_oset_key, @exp, "a")
      # expired, present
      add_to_oset(@exp_oset_key, 0, "c")

      add_session_set(
        "c",
        %{@user_session | id: "c", refresh_expires_at: @now - 5} |> serialize() |> sign()
      )

      assert :ok = RedisStore.upsert(@user_session, @config)

      assert "c" not in list_oset_values(@exp_oset_key)
      assert "c" not in list_hset_values(@session_set_key)
    end

    test "skips already-expired session" do
      session = %{@user_session | refreshed_at: @now + 10000}
      assert :ok = RedisStore.upsert(session, @config)
      assert {:ok, []} = command(~w(KEYS *))
    end

    test "prunes old expired sessions" do
      user_key = old_exp_oset_key(@uid)
      # unexpired, present
      command(["ZADD", user_key, @exp, "a"])
      # expired, somehow present
      command(["ZADD", user_key, 0, "c"])

      assert :ok = RedisStore.upsert(@user_session, @config)

      assert {:ok, keys} = command(["ZRANGE", user_key, 0, -1])
      assert "a" in keys
      assert "c" not in keys
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
      command(["SET", old_session_key(@sid, @uid), @signed_serialized])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, nil} = command(["GET", old_session_key(@sid, @uid)])
    end

    test "also drops the session key in the user's session set" do
      command(["ZADD", old_exp_oset_key(@uid), @exp, old_session_key(@sid, @uid)])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, []} == command(["ZRANGE", old_exp_oset_key(@uid), 0, -1])
    end

    test "can handle negative session ttl" do
      command(["ZADD", old_exp_oset_key(@uid), "3", old_session_key(@sid, @uid)])
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
    end

    test "user's session set ttl correct if deleted session was highest exp session" do
      user_key = old_exp_oset_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["ZADD", user_key, @exp + 5, _to_delete = old_session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl + 5}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
    end

    test "user's session set ttl correct if deleted session not found" do
      user_key = old_exp_oset_key(@uid)
      command(["ZADD", user_key, @exp, "a"])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl, 3
    end

    test "user's session set ttl correct if deleted session was NOT highest exp session" do
      user_key = old_exp_oset_key(@uid)
      command(["ZADD", user_key, @exp + 5, "a"])
      command(["ZADD", user_key, @exp, _to_delete = old_session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl + 5}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, ttl} = command(["TTL", user_key])
      assert_in_delta ttl, @ttl + 5, 3
    end

    test "user's session set removed if deleted session was last session" do
      user_key = old_exp_oset_key(@uid)
      command(["ZADD", user_key, @exp, _to_delete = old_session_key(@sid, @uid)])
      command(["EXPIRE", user_key, "#{@ttl}"])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)

      assert {:ok, 0} = command(["EXISTS", user_key])
    end

    test "deletes session with old key format" do
      command([
        "SET",
        RedisStore.old_session_key(@sid, {to_string(@uid), "full", "charon_"}),
        @signed_serialized
      ])

      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, []} = command(~w(keys *))
    end

    test "deletes session from all sets" do
      insert(@user_session)
      insert(%{@user_session | id: "b"})

      assert :ok = RedisStore.delete("b", @uid, :full, @config)

      assert @user_session |> serialize() |> sign() == get_session_set(@sid)
      assert [@sid, @exp_str] == list_oset_values(@exp_oset_key)
    end
  end

  describe "get_all/3" do
    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      command(["ZADD", old_exp_oset_key(@uid), @exp, "a"])
      command(["SET", "a", @signed_serialized])
      # unexpired, missing
      command(["ZADD", old_exp_oset_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", old_exp_oset_key(@uid), 0, "c"])
      command(["SET", "c", @signed_serialized])
      # expired and missing as it should be
      command(["ZADD", old_exp_oset_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", "user2", @exp, "e"])
      command(["SET", "e", @signed_serialized])
      # unexpired, present, other type
      command(["ZADD", old_exp_oset_key(@uid, :oauth2), @exp, "f"])
      command(["SET", "f", @signed_serialized])

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end

    test "returns the user's new format unexpired, deserialized sessions of requested type" do
      # unexpired, present
      add_session_set(@sid, @user_session |> serialize() |> sign())
      # expired, somehow present
      add_session_set(
        "c",
        %{@user_session | id: "c", refresh_expires_at: @now - 5} |> serialize() |> sign()
      )

      # another user's session
      add_session_set("d", %{@user_session | id: "d", user_id: @uid + 1} |> serialize() |> sign())
      # wrong type
      add_session_set("e", %{@user_session | id: "e", type: :wrong} |> serialize() |> sign())

      assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
    end
  end

  describe "delete_all/3" do
    test "removes all sessions of requested type and the user's session set" do
      # unexpired, present
      command(["ZADD", old_exp_oset_key(@uid), @exp, "a"])
      command(["SET", "a", @signed_serialized])
      # unexpired, missing
      command(["ZADD", old_exp_oset_key(@uid), @exp, "b"])
      # expired, somehow present
      command(["ZADD", old_exp_oset_key(@uid), 0, "c"])
      command(["SET", "c", @signed_serialized])
      # expired and missing as it should be
      command(["ZADD", old_exp_oset_key(@uid), 0, "d"])
      # another user's session
      command(["ZADD", old_exp_oset_key(@uid + 1), @exp, "e"])
      command(["SET", "e", "session_e"])
      # unexpired, present, other type
      command(["ZADD", old_exp_oset_key(@uid, :oauth2), @exp, "f"])
      command(["SET", "f", @signed_serialized])

      assert :ok == RedisStore.delete_all(@uid, :full, @config)
      assert {:ok, keys} = command(~w(KEYS *))

      assert [
               old_exp_oset_key(@uid, :oauth2) |> IO.iodata_to_binary(),
               old_exp_oset_key(@uid + 1) |> IO.iodata_to_binary(),
               "e",
               "f"
             ] == Enum.sort(keys)
    end

    test "removes all sessions of requested type" do
      insert(@user_session)

      assert [@exp_oset_key, @session_set_key] = command(~w(KEYS *)) |> elem(1) |> Enum.sort()

      insert(%{@user_session | type: :oauth2})
      insert(%{@user_session | user_id: @uid + 1})

      assert :ok == RedisStore.delete_all(@uid, :full, @config)

      keys = command(~w(KEYS *)) |> elem(1) |> Enum.sort()
      count = Enum.count(keys)
      assert count == Enum.count(keys -- [@exp_oset_key, @session_set_key])
    end
  end

  describe "migrate_sessions/1" do
    test "signs sessions and reinserts with new storage format" do
      oldest_session_key =
        RedisStore.oldest_session_key("a", {to_string(@uid), "full", "charon_"})

      old_session_key = RedisStore.old_session_key("b", {to_string(@uid), "full", "charon_"})

      command(["ZADD", old_exp_oset_key(@uid), @exp, oldest_session_key])
      command(["SET", oldest_session_key, @serialized])
      command(["ZADD", old_exp_oset_key(@uid), @exp, old_session_key])
      command(["SET", old_session_key, %{@user_session | id: "b"} |> :erlang.term_to_binary()])

      assert capture_log(fn ->
               RedisStore.migrate_sessions(@config)
             end) =~ "Unsigned session"

      assert {:ok, keys} = command(~w(KEYS *))
      assert ["charon_.e.426.full", session_set_key = "charon_.se.426.full"] == Enum.sort(keys)

      assert {:ok, <<"signed.", _mac::256, ".", _session::binary>>} =
               command(["HGET", session_set_key, "a"])

      assert {:ok, <<"signed.", _mac::256, ".", _session::binary>>} =
               command(["HGET", session_set_key, "b"])
    end
  end
end
