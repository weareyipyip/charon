defmodule Charon.Absinthe.HydrateContextPlug do
  @moduledoc """
  Plug to bridge the gap between Plug's conn and Abinthe's context.
  """
  @behaviour Plug

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
      |> then(&Absinthe.Plug.put_options(preauth_conn, context: &1))
    end)
  end
end
