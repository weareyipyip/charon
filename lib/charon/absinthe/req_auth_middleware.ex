defmodule Charon.Absinthe.ReqAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid access token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  use Charon.Constants

  @impl true
  def call(resolution = %{context: %{@auth_error => error}}, config) do
    mod_config = Charon.Absinthe.get_module_config(config)
    mod_config.auth_error_handler.(resolution, error) |> Charon.Internal.resolve_resolution()
  end

  def call(resolution, _config), do: resolution
end
