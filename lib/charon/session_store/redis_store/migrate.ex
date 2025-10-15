defmodule Charon.SessionStore.RedisStore.Migrate do
  @moduledoc """
  Migrate Redis data older to newer data formats.
  """
  alias Charon.SessionStore.RedisStore.ConnectionPool
  alias Charon.Config
  alias Charon.SessionStore.RedisStore
  alias RedisStore.{RedisClient}
  import RedisStore.{Config, StoreImpl}

  @type migrate_opt :: {:batch_size, pos_integer()} | {:sessions_per_user, pos_integer()}
  @type migrate_opts :: [migrate_opt()]

  @doc """
  Migrate Redis data from the v3 data format to the v4 data format. This function is idempotent.

  This is a (relatively) slow operation that iterates keys in the instance and does not guarantee atomicity.
  The function IS atomic for each batch, i.e. not all data may be migrated if new sessions are created during a migration run, but users whose sessions ARE migrated, are migrated completely.
  Regardless, it is recommeded that this function is executed during a maintenance window.

  ## Options

  - `:batch_size` (default 200) number of sessions sets (sessions of a single user) to be read in one batch
  - `:sessions_per_user` (default 5) estimation of the maximum average number of sessions per user - used to balance reads and writes
  """
  @spec migrate_v3_to_v4!(Config.t(), migrate_opts()) :: %{count: integer(), failed: integer()}
  def migrate_v3_to_v4!(config, opts \\ []) do
    mod_conf = get_mod_config(config)
    prefix = mod_conf.key_prefix
    signing_key = get_signing_key(mod_conf, config)
    batch_size = opts[:batch_size] || 200
    sessions_per_user = opts[:sessions_per_user] || 5
    conn = ConnectionPool.checkout()

    # the v3 key format is prefix.separator.uid.type (the separator distinguishes between the session/lock/exp sets)
    # the session set separator is "se"
    RedisClient.stream_scan(match: "#{prefix}.se.*", count: batch_size)
    |> Stream.chunk_every(batch_size)
    |> Stream.flat_map(fn set_keys ->
      {:ok, results} =
        set_keys
        |> Enum.flat_map(&[["WATCH", &1], ["HVALS", &1]])
        |> RedisClient.conn_pipeline(conn, true)

      Stream.reject(results, &(&1 == "OK"))
    end)
    |> Stream.flat_map(&Function.identity/1)
    |> Stream.chunk_every(sessions_per_user * batch_size)
    |> Enum.reduce(%{count: 0, failed: 0}, fn sessions, acc ->
      sessions
      |> Enum.reduce({acc, _to_del = %{}, _to_ins = []}, fn serialized, {acc, to_del, to_ins} ->
        acc = inc_map(acc, :count)

        with s = %{} <- serialized |> verify_signature(signing_key) |> maybe_deserialize() do
          to_del = put_map_group(to_del, {s.user_id, s.type}, s.id)
          to_ins = [{s, serialized} | to_ins]
          {acc, to_del, to_ins}
        else
          _ -> {inc_map(acc, :failed), to_del, to_ins}
        end
      end)
      |> then(&migrate(&1, prefix, conn))
    end)
    |> tap(fn _ -> ConnectionPool.checkin(conn) end)
  end

  ###########
  # Private #
  ###########

  defp inc_map(map, key), do: %{map | key => Map.fetch!(map, key) + 1}
  defp put_map_group(map, k, v), do: Map.update(map, k, [v], &[v | &1])

  defp migrate({acc, to_delete, to_insert}, prefix, conn) do
    delete_cmds = delete_cmds(to_delete, prefix)
    insert_cmds = insert_cmds(to_insert, prefix)
    cmds = delete_cmds ++ insert_cmds
    {:ok, _} = RedisClient.conn_transaction_pipeline(cmds, conn, true)
    acc
  end

  defp delete_cmds(to_delete, prefix) do
    Enum.flat_map(to_delete, fn {{uid, type}, ids} ->
      uid = to_string(uid)
      type = Atom.to_string(type)
      ssk = [prefix, ".se.", uid, ?., type]
      locks_key = [prefix, ".l.", uid, ?., type]
      exps_key = [prefix, ".e.", uid, ?., type]

      [["HDEL", ssk | ids], ["HDEL", locks_key | ids], ["ZREM", exps_key | ids]]
    end)
  end

  defp insert_cmds(to_insert, prefix) do
    Enum.map(to_insert, fn {session = %{id: sid}, serialized} ->
      ssk = [prefix, ?., to_string(session.user_id), ?., Atom.to_string(session.type)]
      exp = Integer.to_string(session.refresh_expires_at)
      lock = Integer.to_string(session.lock_version)
      ["HSETEX", ssk, "EXAT", exp, "FIELDS", "2", sid, serialized, "l.#{sid}", lock]
    end)
  end
end
