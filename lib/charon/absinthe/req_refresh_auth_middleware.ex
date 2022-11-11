defmodule Charon.Absinthe.ReqRefreshAuthMiddleware do
  @moduledoc """
  Absinthe middleware to require a valid refresh token.
  Can be used if the context was hydrated by `Charon.Absinthe.HydrateContextPlug`.
  """
  @behaviour Absinthe.Middleware
  use Charon.Constants
  alias Charon.Internal

  @impl true
  def call(resolution = %{context: %{charon_conn: conn}}, config) do
    mod_config = Charon.Absinthe.get_module_config(config)

    conn
    |> clean_conn()
    |> mod_config.refresh_token_pipeline.call(nil)
    |> then(fn
      _unauthenticated_conn = %{private: %{@auth_error => error}} ->
        mod_config.auth_error_handler.(resolution, error) |> Internal.resolve_resolution()

      authenticated_conn = %{assigns: assigns} ->
        context = assigns |> Map.merge(%{charon_conn: authenticated_conn})
        Internal.merge_context(resolution, context)
    end)
  end

  ###########
  # Private #
  ###########

  # clean the conn before passing it through the refresh token pipeline
  # so that errors / assigns etc of the access token pipeline don't influence the result
  defp clean_conn(conn), do: %{conn | private: %{}, assigns: %{}}
end
