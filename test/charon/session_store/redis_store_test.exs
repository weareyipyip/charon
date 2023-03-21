defmodule Charon.SessionStore.RedisStoreTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore
  import Charon.{TestUtils, Internal}
  import Charon.Internal.Crypto
  alias Charon.{TestConfig}
  alias RedisStore.{RedisClient}
  import RedisClient, only: [command: 1]

  @ttl 10
  @now now()
  @exp @now + @ttl
  @exp_str to_string(@exp)
  @mod_conf %{} |> RedisStore.init_config()
  @config %{
    TestConfig.get()
    | session_ttl: :infinite,
      refresh_token_ttl: @ttl,
      optional_modules: %{RedisStore => @mod_conf}
  }
  @sid "a"
  @uid 426
  @user_session test_session(
                  id: @sid,
                  user_id: @uid,
                  refresh_expires_at: @exp,
                  refreshed_at: @now
                )
  @session_set_key session_set_key(@uid)
  @exp_oset_key exp_oset_key(@uid)
  @lock_set_key lock_set_key(@uid)
  @lock_incr_user_session %{@user_session | lock_version: 1}

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({RedisStore, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  defp serialize(session), do: session |> :erlang.term_to_binary()
  defp sign(binary), do: sign_hmac(binary, RedisStore.default_signing_key(@config))
  # defp get(key), do: command(["GET", key]) |> to_result()
  defp list_oset_values(key), do: command(["ZRANGE", key, 0, -1, "WITHSCORES"]) |> to_result()
  defp list_hset_values(key), do: command(["HGETALL", key]) |> to_result()
  defp to_result({:ok, result}), do: result
  defp get_exp(key), do: command(["EXPIRETIME", key]) |> to_result()
  defp set_exp(key, exp), do: 1 = command(["EXPIREAT", key, exp]) |> to_result()
  defp add_to_oset(set_k, score, v), do: 1 = command(["ZADD", set_k, score, v]) |> to_result()
  defp add_to_hash_set(set_k, k, v), do: 1 = command(["HSET", set_k, k, v]) |> to_result()
  defp add_session_set(k, v), do: add_to_hash_set(@session_set_key, k, v)
  defp get_hash_set(set_k, k), do: command(["HGET", set_k, k]) |> to_result()
  defp get_session_set(k), do: get_hash_set(@session_set_key, k)
  defp get_lock_set(k), do: get_hash_set(@lock_set_key, k)

  # defp insert(key, value), do: "OK" = command(["SET", key, value]) |> to_result()

  defp insert(
         session = %{
           id: sid,
           user_id: uid,
           type: type,
           lock_version: lock,
           refresh_expires_at: exp
         }
       ) do
    serialized_signed = session |> serialize() |> sign()
    add_to_hash_set(session_set_key(uid, type), sid, serialized_signed)
    add_to_hash_set(lock_set_key(uid, type), sid, lock)
    add_to_oset(exp_oset_key(uid, type), exp, sid)
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
      add_session_set(@sid, serialize(@user_session))

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end

    test "ignores signed session with invalid signature" do
      invalid = "signed." <> :crypto.strong_rand_bytes(32) <> "." <> serialize(@user_session)
      add_session_set(@sid, invalid)

      assert capture_log(fn ->
               refute RedisStore.get(@sid, @uid, :full, @config)
             end) =~ "Ignored Redis session"
    end

    test "ignores valid session with mismatching properties" do
      # another user's session somehow ends up in this user's session set
      invalid = serialize(%{@user_session | user_id: @uid + 1}) |> sign()
      add_session_set(@sid, invalid)
      refute RedisStore.get(@sid, @uid, :full, @config)
    end
  end

  describe "upsert/3" do
    test "stores session, lock and exp" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @lock_incr_user_session |> serialize() |> sign() == get_session_set(@sid)
      assert "1" == get_lock_set(@sid)
      assert [@sid, @exp_str] == list_oset_values(@exp_oset_key)
    end

    test "sets session sets ttl / exp score" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      assert @exp = get_exp(@exp_oset_key)
      assert @exp = get_exp(@lock_set_key)
      assert @exp = get_exp(@session_set_key)
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

      new_exp = @exp + 10

      assert :ok =
               @lock_incr_user_session
               |> Map.merge(%{extra_payload: %{new: "key"}, refresh_expires_at: new_exp})
               |> RedisStore.upsert(@config)

      assert "signed." <> <<_::256>> <> "." <> new_session = get_session_set(@sid)

      assert new_exp == get_exp(@exp_oset_key)
      assert new_exp == get_exp(@lock_set_key)
      assert new_exp == get_exp(@session_set_key)
      assert [@sid, to_string(new_exp)] == list_oset_values(@exp_oset_key)

      assert %{extra_payload: %{new: "key"}} = new_session |> :erlang.binary_to_term()
    end

    test "does not reduce set expirations" do
      assert :ok = RedisStore.upsert(@user_session, @config)

      far_future = @now + 10000
      set_exp(@exp_oset_key, far_future)
      set_exp(@lock_set_key, far_future)
      set_exp(@session_set_key, far_future)

      assert :ok = RedisStore.upsert(%{@user_session | id: "b"}, @config)

      assert far_future == get_exp(@exp_oset_key)
      assert far_future == get_exp(@lock_set_key)
      assert far_future == get_exp(@session_set_key)
    end

    test "prunes expired sessions" do
      # unexpired, present
      add_to_oset(@exp_oset_key, @exp, "a")
      # expired, present
      add_to_oset(@exp_oset_key, 0, "c")
      add_to_hash_set(@lock_set_key, "c", "12")

      add_session_set(
        "c",
        %{@user_session | id: "c", refresh_expires_at: @now - 5} |> serialize() |> sign()
      )

      assert :ok = RedisStore.upsert(@user_session, @config)

      assert "c" not in list_oset_values(@exp_oset_key)
      assert "c" not in list_hset_values(@session_set_key)
      assert "c" not in list_hset_values(@lock_set_key)
    end

    test "only prunes once per hour" do
      assert :ok = RedisStore.upsert(@user_session, @config)

      # expired, present
      add_to_oset(@exp_oset_key, 0, "c")
      add_to_hash_set(@lock_set_key, "c", "12")

      assert :ok = RedisStore.upsert(@lock_incr_user_session, @config)

      assert "c" in list_oset_values(@exp_oset_key)
      assert "c" in list_hset_values(@lock_set_key)
    end

    test "skips already-expired session" do
      session = %{@user_session | refreshed_at: @now + 10000}
      assert :ok = RedisStore.upsert(session, @config)
      assert {:ok, []} = command(~w(KEYS *))
    end

    test "implements optimistic locking with respect to input session" do
      assert :ok = RedisStore.upsert(@user_session, @config)
      # stored lock_version has been increased
      assert {:error, :conflict} = RedisStore.upsert(@user_session, @config)
      assert @lock_incr_user_session |> serialize() |> sign() == get_session_set(@sid)
      assert "1" == get_lock_set(@sid)
      assert [@sid, @exp_str] == list_oset_values(@exp_oset_key)
    end
  end

  describe "delete/4" do
    test "returns ok when not found" do
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
    end

    test "deletes session from all sets" do
      insert(@user_session)
      insert(%{@user_session | id: "b"})

      assert :ok = RedisStore.delete("b", @uid, :full, @config)

      assert @user_session |> serialize() |> sign() == get_session_set(@sid)
      assert "0" == get_lock_set(@sid)
      assert [@sid, @exp_str] == list_oset_values(@exp_oset_key)
    end

    test "all set exps correct if deleted session was highest exp session" do
      insert(@user_session)
      insert(%{@user_session | id: "b", refresh_expires_at: @exp + 10})
      insert(%{@user_session | id: "c", refresh_expires_at: @exp + 20})

      assert :ok = RedisStore.delete("c", @uid, :full, @config)

      # exp reduced to next-in-line highest exp session
      assert @exp + 10 == get_exp(@exp_oset_key)
      assert @exp + 10 == get_exp(@lock_set_key)
      assert @exp + 10 == get_exp(@session_set_key)
    end

    test "all set exps correct(ed) if deleted session not found" do
      insert(@user_session)
      # the set should never have this value, which doesn't match the exp of @user_session
      far_future = @now + 10000
      set_exp(@exp_oset_key, far_future)
      set_exp(@lock_set_key, far_future)
      set_exp(@session_set_key, far_future)

      assert :ok = RedisStore.delete("b", @uid, :full, @config)

      # exp reduced to next-in-line highest exp session
      assert @exp = get_exp(@exp_oset_key)
      assert @exp = get_exp(@lock_set_key)
      assert @exp = get_exp(@session_set_key)
    end

    test "all set exps correct if deleted session was NOT highest exp session" do
      insert(@user_session)
      insert(%{@user_session | id: "b", refresh_expires_at: @exp + 10})
      insert(%{@user_session | id: "c", refresh_expires_at: @exp + 20})

      assert :ok = RedisStore.delete("b", @uid, :full, @config)

      # set exp is unchanged
      assert @exp + 20 == get_exp(@exp_oset_key)
      assert @exp + 20 == get_exp(@lock_set_key)
      assert @exp + 20 == get_exp(@session_set_key)
    end

    test "all sets removed if deleted session was last session" do
      insert(@user_session)
      assert :ok = RedisStore.delete(@sid, @uid, :full, @config)
      assert {:ok, []} = command(~w(KEYS *))
    end
  end

  describe "get_all/3" do
    test "works when no keys" do
      assert [] == RedisStore.get_all(@uid, :full, @config)
    end

    test "returns the user's unexpired, deserialized sessions of requested type" do
      # unexpired, present
      add_session_set(@sid, @user_session |> serialize() |> sign())
      # unsigned
      add_session_set("b", %{@user_session | id: "b"} |> serialize())
      # expired, somehow present
      add_session_set(
        "c",
        %{@user_session | id: "c", refresh_expires_at: @now - 5} |> serialize() |> sign()
      )

      # another user's session
      add_session_set("d", %{@user_session | id: "d", user_id: @uid + 1} |> serialize() |> sign())
      # wrong type
      add_session_set("e", %{@user_session | id: "e", type: :wrong} |> serialize() |> sign())

      assert capture_log(fn ->
               assert [@user_session] == RedisStore.get_all(@uid, :full, @config)
             end) =~ "Ignored Redis session"
    end
  end

  describe "delete_all/3" do
    test "works when no keys" do
      assert :ok == RedisStore.delete_all(@uid, :full, @config)
      assert {:ok, []} = command(~w(KEYS *))
    end

    test "works when no sessions" do
      add_to_oset(@exp_oset_key, @exp, @sid)
      add_to_hash_set(@lock_set_key, @sid, 12)
      assert :ok == RedisStore.delete_all(@uid, :full, @config)
      assert {:ok, []} = command(~w(KEYS *))
    end

    test "removes all sessions of requested type" do
      insert(@user_session)

      assert [@exp_oset_key, @lock_set_key, @session_set_key] =
               command(~w(KEYS *)) |> elem(1) |> Enum.sort()

      insert(%{@user_session | type: :oauth2})
      insert(%{@user_session | user_id: @uid + 1})

      assert :ok == RedisStore.delete_all(@uid, :full, @config)

      keys = command(~w(KEYS *)) |> elem(1) |> Enum.sort()
      count = Enum.count(keys)
      assert count == Enum.count(keys -- [@exp_oset_key, @lock_set_key, @session_set_key])
    end
  end
end
