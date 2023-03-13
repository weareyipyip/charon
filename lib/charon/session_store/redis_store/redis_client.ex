if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore.RedisClient do
    @moduledoc false
    require Logger
    alias Charon.SessionStore.RedisStore.ConnectionPool

    @type command :: command
    @type connection :: atom | pid | {atom, any} | {:via, atom, any}
    @type redix_result ::
            {:ok, Redix.Protocol.redis_value()}
            | {:error, atom | Redix.Error.t() | Redix.ConnectionError.t()}

    @doc """
    Execute a Redis command using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec command(command, boolean, keyword) :: redix_result
    def command(command, debug_log? \\ false, redix_opts \\ []) do
      ConnectionPool.transaction(&conn_command(&1, command, debug_log?, redix_opts))
    end

    @doc """
    Execute a Redis command using a previously checked-out connection.

    Use `Charon.SessionStore.RedisStore.ConnectionPool.checkout/2` to get a connection,
    and use `Charon.SessionStore.RedisStore.ConnectionPool.checkin/1` to return the connection to the pool.
    """
    @spec conn_command(connection, command, boolean, keyword) :: redix_result
    def conn_command(conn, command, debug_log? \\ false, redix_opts \\ []) do
      Redix.command(conn, command, redix_opts) |> tap_maybe_log(command, debug_log?)
    end

    @doc """
    Execute a list of Redis commands using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec pipeline([command], boolean, keyword) :: redix_result
    def pipeline(commands, debug_log? \\ false, redix_opts \\ []) do
      ConnectionPool.transaction(&conn_pipeline(&1, commands, debug_log?, redix_opts))
    end

    @doc """
    Execute a list of Redis commands using a previously checked-out connection.

    Use `Charon.SessionStore.RedisStore.ConnectionPool.checkout/2` to get a connection,
    and use `Charon.SessionStore.RedisStore.ConnectionPool.checkin/1` to return the connection to the pool.
    """
    @spec conn_pipeline(connection, [command], boolean, keyword) :: redix_result
    def conn_pipeline(conn, commands, debug_log? \\ false, redix_opts \\ []) do
      Redix.pipeline(conn, commands, redix_opts) |> tap_maybe_log(commands, debug_log?)
    end

    ###########
    # Private #
    ###########

    defp tap_maybe_log(result, command, debug_log?) do
      maybe_log(result, command, debug_log?)
      result
    end

    defp maybe_log(_result, _command, false), do: :ok

    defp maybe_log(result = {:error, _}, command, _) do
      Logger.error("Redis command #{inspect(command)}, result: #{inspect(result)}")
    end

    defp maybe_log(result, command, _) do
      Logger.debug(fn -> "Redis command #{inspect(command)}, result: #{inspect(result)}" end)
    end
  end
end
