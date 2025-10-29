defmodule Charon.Supervisor do
  alias Charon.ConnectionPool
  alias Charon.RedisClient, as: RedisClientMod
  alias Charon.SessionStore.RedisStore, as: RedisStoreMod
  use Supervisor

  def start_link(opts) do
    base_mod = Keyword.fetch!(opts, :base_module)
    name = opts[:name] || Module.concat(base_mod, Supervisor)
    Supervisor.start_link(__MODULE__, %{base_module: base_mod, config: opts[:config]}, name: name)
  end

  @impl true
  def init(%{base_module: base_mod, config: config}) do
    # conflict_guard_name = Module.concat(base_mod, ConflictGuard)
    # config_mod = Module.concat(base_mod, Store)
    # machine_id = config_mod.get(:machine_id)
    # conflict_guard_opts = [name: conflict_guard_name, machine_id: machine_id]

    children =
      [
        # {NoNoncense.MachineId.ConflictGuard, conflict_guard_opts}
      ]
      # |> maybe_add_redis_store(base_mod, config)
      |> maybe_add_connection_pool(base_mod, config)

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp maybe_add_redis_store(children, base_mod, _config = %{session_store_module: RedisStoreMod}) do
    store_name = Module.concat(base_mod, SessionStore.RedisStore)

    # children = maybe_add_connection_pool(children, store_name, config)
    [{RedisStoreMod, [name: store_name]} | children]
  end

  defp maybe_add_redis_store(children, _, _), do: children

  defp maybe_add_connection_pool(
         children,
         base_mod,
         _config = %{optional_modules: %{RedisClientMod => conf}}
       ) do
    [
      name: conf.pool_name,
      size: conf.pool_size,
      max_overflow: conf.pool_max_overflow,
      worker: Redix,
      worker_args: conf.redix_opts
    ]
    |> ConnectionPool.child_spec()
    |> then(fn child_spec -> [child_spec | children] end)
  end

  defp maybe_add_connection_pool(children, _, _), do: children
end
