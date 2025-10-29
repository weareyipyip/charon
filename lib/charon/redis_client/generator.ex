defmodule Charon.RedisClient.Generator do
  @moduledoc false

  def generate!(base_mod, config) do
    quote generated: true,
          location: :keep,
          bind_quoted: [
            base_mod: base_mod,
            module_name: Module.concat(base_mod, RedisClient),
            moddoc: @moduledoc,
            pool_name: Charon.RedisClient.get_mod_conf!(config).pool_name
          ] do
      defmodule module_name do
        @moduledoc moddoc
        @with_conn &pool_name.transaction/1

        defdelegate command(conn_or_resolvable \\ @with_conn, command, redix_opts),
          to: Charon.RedisClient

        def command(command), do: command(command, [])

        defdelegate pipeline(conn_or_resolvable \\ @with_conn, commands, redix_opts),
          to: Charon.RedisClient

        def pipeline(commands), do: pipeline(commands, [])

        defdelegate transaction_pipeline(conn_or_resolvable \\ @with_conn, commands, redix_opts),
          to: Charon.RedisClient

        def transaction_pipeline(commands), do: transaction_pipeline(commands, [])

        defdelegate stream_scan(conn_or_resolvable \\ @with_conn, opts),
          to: Charon.RedisClient

        def stream_scan(), do: stream_scan([])
      end
    end
    |> Code.compile_quoted()
  end
end
