if Code.ensure_loaded?(Redix) do
  defmodule Charon.RedisClient do
    @moduledoc """
    Redis client that extends bare `Redix` with some convenience features.
    """
    use Charon.OptMod
    require Logger

    @type command :: Redix.command()
    @type conn_or_resolvable ::
            Redix.connection() | Charon.Config.t() | ((Redix.connection() -> any()) -> any())
    @type redix_result ::
            {:ok, Redix.Protocol.redis_value()}
            | {:error, atom | Redix.Error.t() | Redix.ConnectionError.t()}

    @doc """
    Execute a Redis command using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec command(conn_or_resolvable, command, keyword) :: redix_result
    def command(conn_or_resolvable, command, redix_opts \\ []) do
      exec_with_conn(conn_or_resolvable, fn conn ->
        Redix.command(conn, command, redix_opts) |> tap_emit(command)
      end)
    end

    @doc """
    Execute a list of Redis commands using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec pipeline(conn_or_resolvable, [command], keyword) :: redix_result
    def pipeline(conn_or_resolvable, commands, redix_opts \\ []) do
      exec_with_conn(conn_or_resolvable, fn conn ->
        Redix.pipeline(conn, commands, redix_opts) |> tap_emit(commands)
      end)
    end

    @doc """
    Execute a list of Redis commands as a MULTI/EXEC transaction using any connection from `Charon.SessionStore.RedisStore.ConnectionPool`.
    """
    @spec transaction_pipeline(conn_or_resolvable, [command], keyword) :: redix_result
    def transaction_pipeline(conn_or_resolvable, commands, redix_opts \\ []) do
      exec_with_conn(conn_or_resolvable, fn conn ->
        Redix.transaction_pipeline(conn, commands, redix_opts) |> tap_emit(commands)
      end)
    end

    @doc """
    Execute Redis' SCAN command and stream the results.

    Options `:type`, `:count` and `:match` can be passed in and map to the command's [options](https://redis.io/docs/latest/commands/scan/). Note that using count only influences the batch size in which results are returned by Redis, and results are streamed one-by-one regardless.
    """
    @spec stream_scan(conn_or_resolvable, keyword()) :: Enum.t()
    def stream_scan(conn_or_resolvable, opts \\ []) do
      exec_with_conn(conn_or_resolvable, fn conn ->
        cmd_opts = prefix_opts(opts, ~w(type count match)a)

        Stream.unfold(_cursor = nil, fn
          "0" -> _terminate = nil
          cursor -> scan(conn, cursor, cmd_opts)
        end)
        # flatten the results to emit a stream of keys, not a stream of batches of keys
        |> Stream.flat_map(&Function.identity/1)
      end)
    end

    defp prefix_opts(opts, fields) do
      Enum.reduce(fields, [], fn fld, cmd ->
        if value = opts[fld], do: [String.upcase("#{fld}"), to_string(value) | cmd], else: cmd
      end)
    end

    defp scan(conn, nil, cmd_opts), do: scan(conn, "0", cmd_opts)

    defp scan(conn, cursor, cmd_opts) do
      command(conn, ["SCAN", cursor | cmd_opts]) |> proc_scan_res()
    end

    defp proc_scan_res({:ok, [cursor, results]}), do: {results, cursor}
    defp proc_scan_res(other), do: raise("Unexpected scan result: #{inspect(other)}")

    def attach_default_handler(opts \\ []) do
      debug_log? = opts[:debug_log?] || false

      :telemetry.attach_many(
        "charon-redisclient-telemetry-handler",
        [[:charon, :redis_client, :ok], [:charon, :redis_client, :error]],
        &__MODULE__.handle_telemetry_event/4,
        debug_log?
      )
    end

    @doc false
    def handle_telemetry_event(
          [:charon, :redis_client, :error],
          _measurements,
          metadata,
          _debug_log?
        ) do
      %{command: command, result: result} = metadata
      Logger.error("Redis command #{inspect(command)}, result: #{inspect(result)}")
    end

    def handle_telemetry_event([:charon, :redis_client, :ok], _measurements, metadata, true) do
      %{command: command, result: result} = metadata
      Logger.debug("Redis command #{inspect(command)}, result: #{inspect(result)}")
    end

    def handle_telemetry_event(_, _, _, _), do: :ok

    @impl OptMod
    def init_config(config) do
      mod_conf = get_mod_conf(config)
      mod_conf = struct!(__MODULE__.Config, mod_conf)
      Charon.OptMod.put_mod_conf(config, __MODULE__, mod_conf)
    end

    @impl OptMod
    defdelegate generate!(base_mod, config), to: __MODULE__.Generator

    ###########
    # Private #
    ###########

    @compile {:inline, exec_with_conn: 2}
    defp exec_with_conn(config = %Charon.Config{}, fun) do
      get_mod_conf!(config).pool_name.transaction |> exec_with_conn(fun)
    end

    defp exec_with_conn(with_conn, fun) when is_function(with_conn, 1), do: with_conn.(fun)
    defp exec_with_conn(conn, fun), do: fun.(conn)

    @compile {:inline, tap_emit: 2}
    defp tap_emit(result, command) do
      emit(result, command)
      result
    end

    defp emit(result = {:error, _}, command), do: emit(:error, command, result)
    defp emit(result, command), do: emit(:ok, command, result)

    defp emit(event, command, result) do
      [:charon, :redis_client, event]
      |> :telemetry.execute(%{count: 1}, %{command: command, result: result})
    end
  end
end
