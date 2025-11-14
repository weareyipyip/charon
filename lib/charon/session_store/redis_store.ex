if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore do
    @supervisor_opts_docs """
      - `:name` (default module name) name of the supervisor
      - `:pool_size` (default 10) total number of (local) normal workers
      - `:pool_max_overflow` (default 5) max number of (local) extra workers in case of high load
      - `:redix_opts` passed to `Redix.start_link/1`

    The pool and its config options are local to the Elixir/OTP node,
    so if you use multiple nodes, the total connection count to Redis maxes out at
    `(pool_size + pool_max_overflow) * number_of_nodes`.
    """

    @moduledoc """
    A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
    In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

    ## Redis requirements

    This module requires Redis >= 8.0.0 or Valkey >= 9.0.0 or another Redis-compatible key-value store with support for [HSETEX](https://redis.io/docs/latest/commands/hsetex/) and related Redis 8 commands, and needs permissions to create Redis functions.
    The optimistic-locking functionality of the store was not designed with a Redis cluster in mind
    and will behave unpredictably when used with a distributed Redis deployment.
    Using a failover-replica should be fine, however.
    The Redis functions are registered with a name that includes the hashed Charon version,
    to make sure that the called function matches the expected code,
    and multiple Charon deployments can share a Redis instance.

    ## Config

    Additional config is required for this module (see `Charon.SessionStore.RedisStore.Config`):

        Charon.Config.from_enum(
          ...,
          optional_modules: %{
            Charon.SessionStore.RedisStore => %{
              key_prefix: "charon_",
              get_signing_key: &RedisStore.default_signing_key/1
            }
          }
        )

    The following options are supported:
      - `:key_prefix` (optional). A string prefix for the Redis keys that are sessions.
      - `:get_signing_key` (optional). A getter/1 that returns the key that is used to sign and verify serialized session binaries.

    ## Initialize store

    RedisStore uses a connection pool and has to register Redis functions on startup.
    In order to initialize it, you must add RedisStore to your application's supervision tree.

        # in application.ex
        def start(_, ) do
          redix_opts = [host: "localhost", port: 6379, password: "supersecret", database: 0]

          children = [
            ...
            {Charon.SessionStore.RedisStore, pool_size: 15, redix_opts: redix_opts},
            ...
          ]

          opts = [strategy: :one_for_one, name: MyApp.Supervisor]
          Supervisor.start_link(children, opts)
        end

    ### Options
    #{@supervisor_opts_docs}

    ## Session signing

    In order to offer some defense-in-depth against a compromised Redis server,
    the serialized sessions are signed using a HMAC. The key is derived from the Charon
    base secret, but can be overridden in the config. This is not usually necessary, except
    when you're changing the base secret and still want to access your sessions.
    It is debatable, of course, in case your Redis server is compromised,
    if your application server holding the signing key can still be considered secure.
    However, given that there are no real drawbacks to using signed session binaries,
    since the performance cost is negligible, no extra config is needed, it is easy to implement,
    and defense-in-depth is a good guiding principle, RedisStore implements this feature anyway.

    ## Implementation details

    RedisStore stores sessions until their associated refresh token(s) expire.
    That means that `:refresh_expires_at` is used to determine if a session is "alive",
    not `:expires_at`.
    This makes sense, because a session without a valid refresh token is effectively useless,
    and it means we can support "infinite lifetime" sessions while still pruning sessions that aren't used.
    This is one reason to set `:refresh_ttl` to a limited value, no more than six months is recommended.

    Last but not least, [Redis 7 functions](https://redis.io/docs/manual/programmability/functions-intro/)
    are used to implement some features, specifically optimistic locking, and to ensure all callbacks
    use only a single round-trip to the Redis instance.
    """
    use Supervisor
    alias Charon.SessionStore.Behaviour, as: SessionStoreBehaviour
    @behaviour SessionStoreBehaviour
    alias Charon.{Config, Utils}
    alias __MODULE__.{LuaFunctions, ConnectionPool, StoreImpl}
    alias Utils.{KeyGenerator, PersistentTermCache}
    require Logger

    @doc """
    Start the RedisStore supervisor, which registeres all required Redis functions and initiates the connection pool.

    ## Options
    #{@supervisor_opts_docs}
    """
    @spec start_link(keyword) :: :ignore | {:error, any} | {:ok, pid}
    def start_link(opts \\ []) do
      name = opts[:name] || __MODULE__
      size = opts[:pool_size] || 10
      max_overflow = opts[:pool_max_overflow] || 5
      redix_opts = opts[:redix_opts] || []

      :ok = LuaFunctions.register_functions(redix_opts)

      init_arg = [
        pool_opts: [
          size: size,
          max_overflow: max_overflow,
          redix_opts: redix_opts,
          name: String.to_atom("#{name}.Pool")
        ]
      ]

      Supervisor.start_link(__MODULE__, init_arg, name: name)
    end

    @doc false
    @impl Supervisor
    def init(opts) do
      [{ConnectionPool, opts[:pool_opts]}] |> Supervisor.init(strategy: :one_for_one)
    end

    @impl SessionStoreBehaviour
    defdelegate get(session_id, user_id, type, config), to: StoreImpl

    @impl SessionStoreBehaviour
    defdelegate upsert(session, config), to: StoreImpl

    @impl SessionStoreBehaviour
    defdelegate delete(session_id, user_id, type, config), to: StoreImpl

    @impl SessionStoreBehaviour
    defdelegate get_all(user_id, type, config), to: StoreImpl

    @impl SessionStoreBehaviour
    defdelegate delete_all(user_id, type, config), to: StoreImpl

    @doc false
    def init_config(enum), do: __MODULE__.Config.from_enum(enum)

    @doc """
    Get the default session signing key that is used if config option `:get_signing_key` is not set explicitly.
    """
    @spec default_signing_key(Config.t()) :: binary
    def default_signing_key(config) do
      PersistentTermCache.get_or_create(__MODULE__, fn ->
        KeyGenerator.derive_key(config.get_base_secret.(), "RedisStore HMAC")
      end)
    end
  end
else
  defmodule Charon.SessionStore.RedisStore do
    @message "Optional dependencies `:redix` and `:poolboy` must be loaded to use this module."
    @moduledoc @message

    def get(_, _, _, _), do: raise(@message)
    def upsert(_, _), do: raise(@message)
    def delete(_, _, _, _), do: raise(@message)
    def get_all(_, _, _), do: raise(@message)
    def delete_all(_, _, _), do: raise(@message)

    def init_config(_), do: raise(@message)
    def default_signing_key(_), do: raise(@message)
  end
end
