defmodule Charon.Absinthe.ReqAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid access token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  alias Charon.Utils

  @impl true
  def call(%{context: %{user_id: _}} = resolution, _config), do: resolution

  def call(resolution, config) do
    error = Utils.get_auth_error(resolution.context.access_token_pipeline_conn)
    mod_config = Charon.Absinthe.get_module_config(config)
    mod_config.auth_error_handler(resolution, error)
  end
end
