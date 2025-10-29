defmodule Charon.OptMod do
  alias Charon.Config

  @callback init_config(config :: Config.t()) :: Config.t()

  # @doc """
  # Check / process config at compile time to allow module generation.
  # """
  # @callback compile_init!(config :: Config.t()) :: Config.t()

  # @callback runtime_init!(compile_conf :: Config.t(), runtime_conf :: Config.t()) :: Config.t()

  @callback generate!(base_module :: module(), compile_config :: Config.t()) :: any()

  @doc """
  Merge new config for an optional module into the base `Charon.Config`.
  """
  @spec put_mod_conf(Charon.Config.t(), module(), any()) :: Charon.Config.t()
  def put_mod_conf(config = %{optional_modules: opt_mods}, module, mod_conf) do
    %{config | optional_modules: Map.put(opt_mods, module, mod_conf)}
  end

  def merge_configs(opt_mods_a, opt_mods_b) do
    Enum.reduce(opt_mods_b, opt_mods_a, fn {module, mod_conf_b}, opt_mods ->
      mod_conf_a = Map.get(opt_mods, module, %{})

      mod_conf_b
      # |> to_map()
      |> Enum.reduce(mod_conf_a, fn {k, v}, mod_conf_a -> Map.put(mod_conf_a, k, v) end)
      |> then(fn mod_conf -> Map.put(opt_mods, module, mod_conf) end)
    end)
  end

  defp to_map(struct) when is_struct(struct), do: Map.from_struct(struct) |> to_map()
  defp to_map(enum), do: Map.new(enum)

  # @doc false
  # def def_runtime_init!(compile_conf, runtime_conf, module) do
  #   compile_mod_conf = compile_conf.optional_modules[module] || %{}
  #   runtime_mod_conf = runtime_conf.optional_modules[module] || %{}
  #   mod_conf = Enum.into(runtime_mod_conf, compile_mod_conf)
  #   put_mod_conf(runtime_conf, module, mod_conf)
  # end

  defmacro __using__(_opts) do
    quote do
      alias Charon.OptMod
      @behaviour OptMod

      # def compile_init!(config) do
      #   OptMod.put_mod_conf(config, __MODULE__, config.optional_modules[__MODULE__] || %{})
      # end

      # def runtime_init!(compile_conf, runtime_conf),
      #   do: OptMod.def_runtime_init!(compile_conf, runtime_conf, __MODULE__)

      def generate!(_, _), do: []

      def init_config(config), do: config

      @doc "Get the config for this optional module from the base `Charon.Config`."
      @compile {:inline, get_mod_conf!: 1}
      def get_mod_conf!(_config = %{optional_modules: %{__MODULE__ => mod_conf}}), do: mod_conf

      def get_mod_conf(_config = %{optional_modules: opt_mods}, default \\ []),
        do: Map.get(opt_mods, __MODULE__, default)

      defoverridable OptMod
    end
  end
end
