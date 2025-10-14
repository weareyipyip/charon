defmodule Charon.SessionStore.RedisStore.MigrateV3 do
  @moduledoc """
  Migrate Redis data from the v3 data format to the v4 data format.
  """
  alias Charon.SessionStore.RedisStore
  alias RedisStore.{RedisClient, StoreImpl}
  import RedisStore.Config

  @doc """
  Migrate Redis data from the v3 data format to the v4 data format. This function is idempotent.

  This is a (relatively) slow operation that iterates keys in the instance and does not guarantee atomicity.
  This function should be executed during a maintenance window.
  """
  @spec migrate_v3_to_v4(Charon.Config.t()) :: map()
  def migrate_v3_to_v4(config) do
    mod_conf = get_mod_config(config)
    prefix = mod_conf.key_prefix
    signing_key = StoreImpl.get_signing_key(mod_conf, config)

    # the v3 key format is prefix.separator.uid.type (the separator distinguishes between the session/lock/exp sets)
    # the session set separator is "se"
    scan_to_stream("#{prefix}.se.*")
    |> Stream.chunk_every(100)
    |> Stream.flat_map(fn session_set_keys ->
      {:ok, session_sets} = session_set_keys |> Enum.map(&["HVALS", &1]) |> RedisClient.pipeline()
      session_sets
    end)
    |> Stream.flat_map(&Function.identity/1)
    |> Stream.chunk_every(1000)
    |> Enum.reduce(%{count: 0, failed: 0}, fn sessions, acc ->
      sessions
      |> Enum.reduce({acc, _to_del = %{}}, fn serialized, {acc, to_del} ->
        acc = %{acc | count: acc.count + 1}

        with sig_result = StoreImpl.verify_signature(serialized, signing_key),
             s = %{} <- StoreImpl.maybe_deserialize(sig_result),
             :ok <- StoreImpl.upsert(s, config) do
          {acc, Map.update(to_del, {s.user_id, s.type}, [s.id], &[s.id | &1])}
        else
          _ -> {%{acc | failed: acc.failed + 1}, to_del}
        end
      end)
      |> then(&delete_old(&1, prefix))
    end)
  end

  defp scan_to_stream(pattern) do
    Stream.resource(
      fn -> {nil, RedisStore.ConnectionPool.checkout()} end,
      fn
        last_result = {"0", _} -> {:halt, last_result}
        {cursor, conn} -> scan(conn, pattern, cursor) |> scan_res_to_resource_res(conn)
      end,
      fn {_, conn} -> RedisStore.ConnectionPool.checkin(conn) end
    )
  end

  defp scan(conn, pattern, cursor) do
    ["SCAN", cursor || "0", "MATCH", pattern, "COUNT", "1000"] |> RedisClient.conn_command(conn)
  end

  defp scan_res_to_resource_res(result, conn)
  defp scan_res_to_resource_res({:ok, [cursor, results]}, conn), do: {results, {cursor, conn}}
  defp scan_res_to_resource_res(other, _), do: raise("Unexpected scan result: #{inspect(other)}")

  defp delete_old({acc, to_delete}, prefix) do
    {:ok, _} =
      to_delete
      |> Enum.flat_map(fn {{uid, type}, ids} ->
        ssk = "#{prefix}.se.#{uid}.#{type}"
        locks_key = "#{prefix}.l.#{uid}.#{type}"
        exps_key = "#{prefix}.e.#{uid}.#{type}"

        [["HDEL", ssk | ids], ["HDEL", locks_key | ids], ["ZREM", exps_key | ids]]
      end)
      |> RedisClient.pipeline(true)

    acc
  end
end
