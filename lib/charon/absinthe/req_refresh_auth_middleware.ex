defmodule Charon.Absinthe.ReqRefreshAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid refresh token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  use Charon.Constants
  alias Charon.Internal

  @impl true
  def call(resolution = %{context: context = %{charon_conn: conn}}, config) do
    mod_config = Charon.Absinthe.get_module_config(config)
    resolution = clean_resolution(resolution, context)

    conn
    |> clean_conn()
    |> mod_config.refresh_token_pipeline.call(nil)
    |> then(fn
      unauthenticated_conn = %{private: %{@auth_error => error}} ->
        resolution
        |> mod_config.auth_error_handler.(error)
        |> Internal.merge_context(%{charon_conn: unauthenticated_conn})
        |> Internal.resolve_resolution()

      authenticated_conn = %{assigns: assigns} ->
        resolution
        |> Internal.merge_context(Map.merge(assigns, %{charon_conn: authenticated_conn}))
    end)
  end

  ###########
  # Private #
  ###########

  # clean the conn before passing it through the refresh token pipeline
  # so that errors / assigns etc of the access token pipeline don't influence the result
  defp clean_conn(conn), do: %{conn | private: %{}, assigns: %{}}

  # clean resolution's context before returning it
  # so that an auth error set by the access token pipeline doesn't end up in it
  defp clean_resolution(resolution, context),
    do: %{resolution | context: Map.delete(context, @auth_error)}
end
