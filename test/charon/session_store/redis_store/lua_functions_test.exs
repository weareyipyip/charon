defmodule Charon.SessionStore.RedisStore.LuaFunctionsTest do
  use ExUnit.Case
  alias Charon.SessionStore.RedisStore
  alias RedisStore.{LuaFunctions, RedisClient}
  alias Charon.Internal

  @ttl 10
  @now Internal.now()
  @exp @now + @ttl
  @exp_str to_string(@exp)
  @sid "a"
  @exp_oset_key "exp_oset"
  @session_set_key "session_set"
  @lock_set_key "lock_set"
  @prune_lock_key "prune_lock"

  defp to_result({:ok, result}), do: result
  defp exec_cmd(cmd), do: cmd |> RedisClient.command() |> to_result()
  defp add_hash_set(set_k, k, v), do: ["HSET", set_k, k, v] |> exec_cmd()
  defp add_sort_set(set_k, k, s), do: ["ZADD", set_k, s, k] |> exec_cmd()
  defp get_exp(key), do: ["EXPIRETIME", key] |> exec_cmd()
  defp set_exp(key, exp), do: 1 = ["EXPIREAT", key, exp] |> exec_cmd()

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({RedisStore, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  describe "resolve_set_exps_cmd" do
    test "works when nothing found" do
      assert [0, 0, 0] =
               LuaFunctions.resolve_set_exps_cmd(@session_set_key, @exp_oset_key, @lock_set_key)
               |> exec_cmd()
    end

    test "works when only expiration set found" do
      add_sort_set(@exp_oset_key, @sid, @exp)
      add_sort_set(@exp_oset_key, "other", @exp - 5)

      assert [0, 1, 0] =
               LuaFunctions.resolve_set_exps_cmd(@session_set_key, @exp_oset_key, @lock_set_key)
               |> exec_cmd()

      assert @exp == get_exp(@exp_oset_key)
    end

    test "works when only session set found" do
      add_hash_set(@session_set_key, @sid, "session")

      assert [0, 0, 0] =
               LuaFunctions.resolve_set_exps_cmd(@session_set_key, @exp_oset_key, @lock_set_key)
               |> exec_cmd()

      assert -1 == get_exp(@session_set_key)
    end

    test "sets session set, exp set and lock set expiration" do
      add_hash_set(@session_set_key, @sid, "session")
      add_sort_set(@exp_oset_key, @sid, @exp)
      add_sort_set(@exp_oset_key, "other", @exp - 5)
      add_hash_set(@lock_set_key, @sid, 5)

      assert [1, 1, 1] =
               LuaFunctions.resolve_set_exps_cmd(@session_set_key, @exp_oset_key, @lock_set_key)
               |> exec_cmd()

      assert @exp == get_exp(@session_set_key)
      assert @exp == get_exp(@exp_oset_key)
      assert @exp == get_exp(@lock_set_key)
    end

    test "works with negative exp (deletes sets)" do
      add_hash_set(@session_set_key, @sid, "session")
      add_sort_set(@exp_oset_key, "other", @now - 5)
      add_hash_set(@lock_set_key, @sid, 5)

      assert [1, 1, 1] =
               LuaFunctions.resolve_set_exps_cmd(@session_set_key, @exp_oset_key, @lock_set_key)
               |> exec_cmd()

      assert -2 == get_exp(@session_set_key)
      assert -2 == get_exp(@exp_oset_key)
      assert -2 == get_exp(@lock_set_key)
    end
  end

  describe "opt_lock_upsert" do
    test "inserts new" do
      assert [1, 1, 1, 1, 1, 1] =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @sid,
                 0,
                 "session",
                 @exp
               )
               |> exec_cmd()

      assert [@sid, "session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@sid, "0"] == exec_cmd(["HGETALL", @lock_set_key])
      assert [@sid, @exp_str] == exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
      assert @exp == get_exp(@session_set_key)
      assert @exp == get_exp(@exp_oset_key)
      assert @exp == get_exp(@lock_set_key)
    end

    test "returns error on lock conflict" do
      add_hash_set(@session_set_key, @sid, "session")
      set_exp(@session_set_key, @exp)
      add_hash_set(@lock_set_key, @sid, 0)
      set_exp(@lock_set_key, @exp)
      add_sort_set(@exp_oset_key, @sid, @exp)
      set_exp(@exp_oset_key, @exp)

      assert "CONFLICT" =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @sid,
                 0,
                 "new_session",
                 @exp + 10
               )
               |> exec_cmd()

      assert [@sid, "session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@sid, "0"] == exec_cmd(["HGETALL", @lock_set_key])
      assert [@sid, @exp_str] == exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
      assert @exp == get_exp(@session_set_key)
      assert @exp == get_exp(@exp_oset_key)
      assert @exp == get_exp(@lock_set_key)
    end

    test "updates when lock ok" do
      add_hash_set(@session_set_key, @sid, "session")
      set_exp(@session_set_key, @exp)
      add_hash_set(@lock_set_key, @sid, 0)
      set_exp(@lock_set_key, @exp)
      add_sort_set(@exp_oset_key, @sid, @exp)
      set_exp(@exp_oset_key, @exp)

      assert [0, 0, 0, 1, 1, 1] =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @sid,
                 1,
                 "new_session",
                 @exp + 10
               )
               |> exec_cmd()

      assert [@sid, "new_session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@sid, "1"] == exec_cmd(["HGETALL", @lock_set_key])
      assert [@sid, "#{@exp + 10}"] == exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
      assert @exp + 10 == get_exp(@session_set_key)
      assert @exp + 10 == get_exp(@exp_oset_key)
      assert @exp + 10 == get_exp(@lock_set_key)
    end

    test "only increases set exps" do
      add_hash_set(@session_set_key, @sid, "session")
      set_exp(@session_set_key, @exp + 10)
      add_hash_set(@lock_set_key, @sid, 0)
      set_exp(@lock_set_key, @exp + 10)
      add_sort_set(@exp_oset_key, @sid, @exp)
      set_exp(@exp_oset_key, @exp + 10)

      assert [0, 0, 0, 0, 0, 0] =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @sid,
                 1,
                 "new_session",
                 @exp + 5
               )
               |> exec_cmd()

      assert [@sid, "new_session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@sid, "1"] == exec_cmd(["HGETALL", @lock_set_key])
      assert [@sid, "#{@exp + 5}"] == exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
      assert @exp + 10 == get_exp(@session_set_key)
      assert @exp + 10 == get_exp(@exp_oset_key)
      assert @exp + 10 == get_exp(@lock_set_key)
    end
  end

  describe "maybe_prune_expired" do
    test "works with missing keys" do
      assert [0, 0, 0] =
               LuaFunctions.maybe_prune_expired_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @prune_lock_key,
                 @now
               )
               |> exec_cmd()
    end

    test "sets lock" do
      LuaFunctions.maybe_prune_expired_cmd(
        @session_set_key,
        @exp_oset_key,
        @lock_set_key,
        @prune_lock_key,
        @now
      )
      |> exec_cmd()

      assert "1" = ["GET", @prune_lock_key] |> exec_cmd()
    end

    test "prunes expired sessions from all sets" do
      add_hash_set(@session_set_key, @sid, "session")
      add_hash_set(@session_set_key, "expired_session_sid", "session")
      add_hash_set(@lock_set_key, @sid, 0)
      add_hash_set(@lock_set_key, "expired_session_sid", 0)
      add_sort_set(@exp_oset_key, @sid, @exp)
      add_sort_set(@exp_oset_key, "expired_session_sid", @now - 5)

      assert [1, 1, 1] =
               LuaFunctions.maybe_prune_expired_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @prune_lock_key,
                 @now
               )
               |> exec_cmd()

      assert [@sid, "session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@sid, "0"] == exec_cmd(["HGETALL", @lock_set_key])
      assert [@sid, @exp_str] == exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
    end

    test "skips operation if too recent" do
      add_hash_set(@session_set_key, @sid, "session")
      add_hash_set(@session_set_key, "expired_session_sid", "session")
      add_hash_set(@lock_set_key, @sid, 0)
      add_hash_set(@lock_set_key, "expired_session_sid", 0)
      add_sort_set(@exp_oset_key, @sid, @exp)
      add_sort_set(@exp_oset_key, "expired_session_sid", @now - 5)

      # lock!
      ["SET", @prune_lock_key, "1"] |> exec_cmd()

      assert "SKIPPED" =
               LuaFunctions.maybe_prune_expired_cmd(
                 @session_set_key,
                 @exp_oset_key,
                 @lock_set_key,
                 @prune_lock_key,
                 @now
               )
               |> exec_cmd()

      assert [@sid, "session", "expired_session_sid", "session"] ==
               exec_cmd(["HGETALL", @session_set_key])

      assert [@sid, "0", "expired_session_sid", "0"] == exec_cmd(["HGETALL", @lock_set_key])

      assert ["expired_session_sid", "#{@now - 5}", @sid, @exp_str] ==
               exec_cmd(["ZRANGE", @exp_oset_key, 0, -1, "WITHSCORES"])
    end
  end
end
