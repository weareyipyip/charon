defmodule Charon.TokenFactory do
  @moduledoc """
  Entrypoint for `Charon.TokenFactory.Behaviour` implementation.
  All functions delegate to the configured module.
  """
  @behaviour __MODULE__.Behaviour

  @impl true
  def sign(payload, config), do: config.token_factory_module.sign(payload, config)

  @impl true
  def verify(token, config), do: config.token_factory_module.verify(token, config)

  @doc false
  def generate(base_mod) do
    module_name = Module.concat(base_mod, TokenFactory)

    quote generated: true,
          location: :keep,
          bind_quoted: [
            base_mod: base_mod,
            module_name: module_name,
            moddoc: @moduledoc
          ] do
      defmodule module_name do
        @moduledoc moddoc
        @behaviour Charon.TokenFactory.Behaviour

        @impl true
        defdelegate sign(payload, config \\ unquote(base_mod).get_config()),
          to: Charon.TokenFactory

        @impl true
        defdelegate verify(token, config \\ unquote(base_mod).get_config()),
          to: Charon.TokenFactory
      end
    end
    |> Code.compile_quoted()
  end
end
