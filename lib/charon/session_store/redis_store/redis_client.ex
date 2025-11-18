if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore.RedisClient do
    @moduledoc """
    Redis client backed by a connection pool.
    """
    require Logger
    alias Charon.SessionStore.RedisStore.ConnectionPool

    @type command :: Redix.command()
    @type connection :: Redix.connection()
    @type redix_result ::
            {:ok, Redix.Protocol.redis_value()}
            | {:error, atom | Redix.Error.t() | Redix.ConnectionError.t()}

    @doc """
    Execute a Redis command using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec command(command, boolean, keyword) :: redix_result
    def command(command, debug_log? \\ false, redix_opts \\ []) do
      ConnectionPool.transaction(&conn_command(command, &1, debug_log?, redix_opts))
    end

    @doc """
    Execute a Redis command using a previously checked-out connection.

    Either use this command with the connection available inside
    `Charon.SessionStore.RedisStore.ConnectionPool.transaction/2`,
    or use `Charon.SessionStore.RedisStore.ConnectionPool.checkout/2` to get a connection,
    combined with `Charon.SessionStore.RedisStore.ConnectionPool.checkin/1`
    to return the connection to the pool.
    """
    @spec conn_command(command, connection, boolean, keyword) :: redix_result
    def conn_command(command, conn, debug_log? \\ false, redix_opts \\ []) do
      Redix.command(conn, command, redix_opts) |> tap_maybe_log(command, debug_log?)
    end

    @doc """
    Execute a list of Redis commands using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec pipeline([command], boolean, keyword) :: redix_result
    def pipeline(commands, debug_log? \\ false, redix_opts \\ []) do
      ConnectionPool.transaction(&conn_pipeline(commands, &1, debug_log?, redix_opts))
    end

    @doc """
    Execute a list of Redis commands using a previously checked-out connection.

    Either use this command with the connection available inside
    `Charon.SessionStore.RedisStore.ConnectionPool.transaction/2`,
    or use `Charon.SessionStore.RedisStore.ConnectionPool.checkout/2` to get a connection,
    combined with `Charon.SessionStore.RedisStore.ConnectionPool.checkin/1`
    to return the connection to the pool.
    """
    @spec conn_pipeline([command], connection, boolean, keyword) :: redix_result
    def conn_pipeline(commands, conn, debug_log? \\ false, redix_opts \\ []) do
      Redix.pipeline(conn, commands, redix_opts) |> tap_maybe_log(commands, debug_log?)
    end

    @doc """
    Execute a list of Redis commands as a MULTI/EXEC transaction using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @doc since: "4.0.0"
    @spec transaction_pipeline([command], boolean, keyword) :: redix_result
    def transaction_pipeline(commands, debug_log? \\ false, redix_opts \\ []) do
      ConnectionPool.transaction(&conn_transaction_pipeline(commands, &1, debug_log?, redix_opts))
    end

    @doc """
    Execute a list of Redis commands as a MULTI/EXEC transaction using a previously checked-out connection.

    Either use this command with the connection available inside
    `Charon.SessionStore.RedisStore.ConnectionPool.transaction/2`,
    or use `Charon.SessionStore.RedisStore.ConnectionPool.checkout/2` to get a connection,
    combined with `Charon.SessionStore.RedisStore.ConnectionPool.checkin/1`
    to return the connection to the pool.
    """
    @doc since: "4.0.0"
    @spec conn_transaction_pipeline([command], connection, boolean, keyword) :: redix_result
    def conn_transaction_pipeline(commands, conn, debug_log? \\ false, redix_opts \\ []) do
      Redix.transaction_pipeline(conn, commands, redix_opts)
      |> tap_maybe_log(commands, debug_log?)
    end

    @doc """
    Execute Redis' SCAN command and stream the results.

    Options `:type`, `:count` and `:match` can be passed in and map to the command's [options](https://redis.io/docs/latest/commands/scan/). Note that using count only influences the batch size in which results are returned by Redis, and results are streamed one-by-one regardless.

    ## Examples

        iex> stream_scan(match: "myprefix.*") |> Enum.map(&Function.identity/1)
        ["myprefix.a", "myprefix.b"]
    """
    @doc since: "4.0.0"
    @spec stream_scan(keyword()) :: Enum.t()
    def stream_scan(opts \\ []) do
      cmd_opts = prefix_opts(opts, ~w(type count match)a)

      Stream.unfold(_cursor = nil, fn
        "0" -> _terminate = nil
        cursor -> scan(cursor, cmd_opts)
      end)
      # flatten the results to emit a stream of keys, not a stream of batches of keys
      |> Stream.flat_map(&Function.identity/1)
    end

    defp scan(nil, cmd_opts), do: scan("0", cmd_opts)
    defp scan(cursor, cmd_opts), do: ["SCAN", cursor | cmd_opts] |> command() |> proc_scan_res()

    defp proc_scan_res({:ok, [cursor, results]}), do: {results, cursor}
    defp proc_scan_res(other), do: raise("Unexpected scan result: #{inspect(other)}")

    ###########
    # Private #
    ###########

    defp prefix_opts(opts, fields) do
      Enum.reduce(fields, [], fn fld, cmd ->
        if value = opts[fld], do: [String.upcase("#{fld}"), to_string(value) | cmd], else: cmd
      end)
    end

    defp tap_maybe_log(result, command, debug_log?) do
      maybe_log(result, command, debug_log?)
      result
    end

    defp maybe_log(result = {:error, _}, command, _) do
      Logger.error("Redis command #{inspect(command)}, result: #{inspect(result)}")
    end

    defp maybe_log(_result, _command, false), do: :ok

    defp maybe_log(result, command, _) do
      Logger.debug(fn -> "Redis command #{inspect(command)}, result: #{inspect(result)}" end)
    end
  end
end
