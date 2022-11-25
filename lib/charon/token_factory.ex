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
end
