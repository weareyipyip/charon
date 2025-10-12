defmodule Charon.SessionStore.RedisStore.LuaFunctionsTest do
  use ExUnit.Case
  alias Charon.SessionStore.RedisStore
  alias RedisStore.{LuaFunctions, RedisClient}
  alias Charon.Internal

  @ttl 10
  @now Internal.now()
  @exp @now + @ttl
  @sid "a"
  @session_set_key "session_set"
  @lock_key "l.a"

  defp to_result({:ok, result}), do: result
  defp exec_cmd(cmd), do: cmd |> RedisClient.command() |> to_result()
  defp get_exp(key), do: ["EXPIRETIME", key] |> exec_cmd()

  defp hget_exp(set_k, keys),
    do: exec_cmd(["HEXPIRETIME", set_k, "FIELDS", Enum.count(keys)] ++ keys)

  defp add_hash_set_ex(set_k, k, v, exp),
    do: ["HSETEX", set_k, "EXAT", to_string(exp), "FIELDS", "1", k, v] |> exec_cmd()

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({RedisStore, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  describe "opt_lock_upsert" do
    test "inserts new" do
      assert 1 =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @sid,
                 @lock_key,
                 0,
                 "session",
                 @exp
               )
               |> exec_cmd()

      assert [@lock_key, "0", @sid, "session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@exp, @exp] == hget_exp(@session_set_key, [@sid, @lock_key])
    end

    test "returns error on lock conflict" do
      add_hash_set_ex(@session_set_key, @sid, "session", @exp)
      add_hash_set_ex(@session_set_key, @lock_key, 0, @exp)

      assert "CONFLICT" =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @sid,
                 @lock_key,
                 0,
                 "new_session",
                 @exp + 10
               )
               |> exec_cmd()

      assert [@lock_key, "0", @sid, "session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@exp, @exp] == hget_exp(@session_set_key, [@sid, @lock_key])
    end

    test "updates when lock ok" do
      add_hash_set_ex(@session_set_key, @sid, "session", @exp)
      add_hash_set_ex(@session_set_key, @lock_key, 0, @exp)

      assert 1 =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @sid,
                 @lock_key,
                 1,
                 "new_session",
                 @exp + 10
               )
               |> exec_cmd()

      assert [@lock_key, "1", @sid, "new_session"] == exec_cmd(["HGETALL", @session_set_key])
      assert [@exp + 10, @exp + 10] == hget_exp(@session_set_key, [@sid, @lock_key])
    end

    test "does not set set exp" do
      assert 1 =
               LuaFunctions.opt_lock_upsert_cmd(
                 @session_set_key,
                 @sid,
                 @lock_key,
                 0,
                 "session",
                 @exp
               )
               |> exec_cmd()

      assert -1 == get_exp(@session_set_key)
    end
  end
end
