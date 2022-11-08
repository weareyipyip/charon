defmodule Charon.Absinthe.ReqRefreshAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid refresh token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  alias Charon.Utils

  @impl true
  def call(resolution = %{context: context = %{preauth_conn: preauth_conn}}, config) do
    preauth_conn
    |> context.refresh_token_pipeline.call(nil)
    |> then(fn
      authenticated_conn = %{assigns: assigns = %{user_id: _}} ->
        assigns
        |> Map.merge(%{refresh_token_pipeline_conn: authenticated_conn})
        |> then(&Charon.Internal.merge_context(resolution, &1))

      unauthenticated_conn ->
        error = Utils.get_auth_error(unauthenticated_conn)
        mod_config = Charon.Absinthe.get_module_config(config)
        mod_config.auth_error_handler(resolution, error)
    end)
  end
end
