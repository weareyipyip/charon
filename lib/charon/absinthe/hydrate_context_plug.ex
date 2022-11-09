defmodule Charon.Absinthe.HydrateContextPlug do
  @moduledoc """
  Plug to bridge the gap between Plug's conn and Abinthe's context.

  Processes the auth token as an access token, and stores the conn in the context.
  """
  @behaviour Plug
  use Charon.Constants

  @doc false
  @impl true
  def init(config), do: Charon.Absinthe.get_module_config(config)

  @doc false
  @impl true
  def call(preauth_conn, %{access_token_pipeline: access_token_pipeline}) do
    preauth_conn
    |> access_token_pipeline.call(nil)
    |> then(fn processed_conn = %{assigns: assigns} ->
      assigns
      |> Map.merge(%{access_token_pipeline_conn: processed_conn, preauth_conn: preauth_conn})
      |> maybe_set_auth_error(processed_conn)
      |> then(&Absinthe.Plug.put_options(preauth_conn, context: &1))
    end)
  end

  ###########
  # Private #
  ###########

  defp maybe_set_auth_error(map, _conn = %{private: %{@auth_error => error}}) do
    Map.put(map, @auth_error, error)
  end

  defp maybe_set_auth_error(map, _), do: map
end
