defmodule Charon do
  @moduledoc Mix.Project.config()[:description]
  alias Charon.OptMod
  alias Charon.SessionStore
  alias SessionStore.RedisStore, as: RedisStoreMod
  alias Charon.TokenFactory
  alias Charon.ConnectionPool, as: ConPoolMod
  alias Charon.RedisClient, as: RedisClientMod

  defmacro __using__(opts) do
    quote generated: true,
          bind_quoted: [opts: opts, moduledoc: @moduledoc],
          location: :keep do
      @otp_app Keyword.fetch!(opts, :otp_app)
      @moduledoc moduledoc
                 |> String.replace(~r/MyApp\.Charon/, Enum.join(Module.split(__MODULE__), "."))
                 |> String.replace(~r/:my_app/, ":#{@otp_app}")

      # make sure the config module exists (in an empty state at least)
      compile_config = Charon.init_config(@otp_app, __MODULE__)

      init_comp_conf =
        Charon.Config.from_enum(compile_config)
        |> Charon.set_default_pool_name(__MODULE__)
        |> Charon.set_default_client_name(__MODULE__)

      TokenFactory.generate(__MODULE__)
      SessionStore.generate(__MODULE__)
      Charon.maybe_gen_redis_client(init_comp_conf, __MODULE__)
      compile_config = Macro.escape(compile_config)
      init_comp_conf = Macro.escape(init_comp_conf)

      ##########
      # Module #
      ##########

      def child_spec(opts) do
        %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :supervisor}
      end

      def start_link(opts \\ []) do
        config = runtime_init()
        sup_opts = Keyword.merge(opts, base_module: __MODULE__, config: config)
        Charon.Supervisor.start_link(sup_opts)
      end

      def get_config(), do: :persistent_term.get(__MODULE__)

      def runtime_init() do
        compile_config = unquote(compile_config) |> IO.inspect(label: "compile")

        config = Charon.init_config(@otp_app, __MODULE__) |> IO.inspect(label: "runtime")

        opt_mods =
          OptMod.merge_configs(compile_config[:optional_modules], config[:optional_modules])

        config = Keyword.put(config, :optional_modules, opt_mods) |> IO.inspect(label: "merged")

        config =
          Charon.Config.from_enum(config)
          |> Charon.set_default_pool_name(__MODULE__)
          |> Charon.set_default_client_name(__MODULE__)
          |> IO.inspect(label: "init")

        if unquote(init_comp_conf).base_secret == config.base_secret do
          raise "The base secret seems to have been set at compile time, which is insecure. Please provide a unique base secret at runtime."
        end

        if bit_size(config.base_secret) < 512 do
          raise "The base secret is too short. The base secret must be a binary of at least 512 bits."
        end

        :persistent_term.put(__MODULE__, config)
        config
      end

      # defp merge_runtime_opt_mods(compile_conf) do
      #   runtime = Application.get_env(@otp_app, __MODULE__) |> Charon.Config.from_enum()
      #   opt_mods = Map.merge(compile_conf.optional_modules, runtime.optional_modules)
      #   %{runtime | optional_modules: opt_mods}
      # end

      # defp maybe_init_redis_client(
      #        config = %{optional_modules: %{RedisClientMod => mod_conf}},
      #        base_mod
      #      ) do
      #   client_name = Module.concat(base_mod, RedisClient)
      #   pool_name = mod_conf.pool_name || Module.concat(client_name, ConnectionPool)
      #   mod_conf = %{mod_conf | pool_name: pool_name}
      #   Charon.OptMod.put_mod_conf(config, RedisClientMod, mod_conf)
      # end

      # defp maybe_init_redis_client(config, _base_mod), do: config

      # defp maybe_init_redis_store(
      #        config = %{
      #          session_store_module: RedisStoreMod,
      #          optional_modules: opt_mods = %{RedisClientMod => _m, RedisStoreMod => mod_conf}
      #        },
      #        base_mod
      #      ) do
      #   def_client_name = Module.concat(base_mod, RedisClient)
      #   redis_client_module = mod_conf.redis_client_module || def_client_name
      #   mod_conf = %{mod_conf | redis_client_module: redis_client_module}
      #   Charon.OptMod.put_mod_conf(config, RedisStoreMod, mod_conf)
      # end

      # defp maybe_init_redis_store(%{session_store_module: RedisStoreMod}, _) do
      #   raise "RedisClient must be configured to use RedisStore"
      # end

      # defp maybe_init_redis_store(config, _base_mod), do: config
    end
  end

  def init_config(otp_app, module) do
    Application.get_env(otp_app, module)
    # |> Charon.Config.from_enum()
  end

  @doc false
  def maybe_gen_redis_client(config = %{optional_modules: %{RedisClientMod => _}}, base_mod) do
    RedisClientMod.generate!(base_mod, config)
    Module.concat(base_mod, RedisClient) |> ConPoolMod.generate()
  end

  def maybe_gen_redis_client(_, _), do: :ok

  def set_default_pool_name(
        config = %{optional_modules: %{RedisClientMod => mod_conf}},
        base_mod
      ) do
    def_pool_name = Module.concat([base_mod, RedisClient, ConnectionPool])
    pool_name = mod_conf.pool_name || def_pool_name
    mod_conf = %{mod_conf | pool_name: pool_name}
    Charon.OptMod.put_mod_conf(config, RedisClientMod, mod_conf)
  end

  def set_default_pool_name(config, _), do: config

  def set_default_client_name(
        config = %{
          session_store_module: RedisStoreMod,
          optional_modules: %{RedisClientMod => _m, RedisStoreMod => store_conf}
        },
        base_mod
      ) do
    def_client_name = Module.concat(base_mod, RedisClient)
    redis_client_module = store_conf.redis_client_module || def_client_name
    store_conf = %{store_conf | redis_client_module: redis_client_module}
    Charon.OptMod.put_mod_conf(config, RedisStoreMod, store_conf)
  end

  def set_default_client_name(%{session_store_module: RedisStoreMod}, _) do
    raise "RedisClient must be configured to use RedisStore"
  end

  def set_default_client_name(config, _base_mod), do: config
end
