defmodule Charon.Absinthe.ReqRefreshAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid refresh token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  use Charon.Constants
  alias Charon.Internal

  @impl true
  def call(resolution = %{context: %{preauth_conn: preauth_conn}}, config) do
    mod_config = Charon.Absinthe.get_module_config(config)

    preauth_conn
    |> mod_config.refresh_token_pipeline.call(nil)
    |> then(fn
      _unauthenticated_conn = %{private: %{@auth_error => error}} ->
        mod_config.auth_error_handler.(resolution, error) |> Internal.resolve_resolution()

      authenticated_conn ->
        authenticated_conn.assigns
        |> Map.merge(%{refresh_token_pipeline_conn: authenticated_conn})
        |> then(&Internal.merge_context(resolution, &1))
    end)
  end
end
