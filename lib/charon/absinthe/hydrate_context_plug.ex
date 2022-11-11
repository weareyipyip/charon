defmodule Charon.Absinthe.HydrateContextPlug do
  @moduledoc """
  Plug to bridge the gap between Plug's conn and Abinthe's context.

  Processes the auth token as an access token, and stores the conn in the context as `:charon_conn`
  so that it may be used in Absinthe resolvers for manipulation sessions with `Charon.SessionPlugs`.

  Note that no guarantees are offered about the consistency of the assigns/private fields etc of
  this conn struct apart from the Charon-related contents.
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
    |> then(fn conn = %{assigns: assigns} ->
      context = assigns |> Map.merge(%{charon_conn: conn}) |> maybe_add_auth_error(conn)
      Absinthe.Plug.put_options(preauth_conn, context: context)
    end)
  end

  ###########
  # Private #
  ###########

  defp maybe_add_auth_error(map, _conn = %{private: %{@auth_error => error}}) do
    Map.put(map, @auth_error, error)
  end

  defp maybe_add_auth_error(map, _), do: map
end
