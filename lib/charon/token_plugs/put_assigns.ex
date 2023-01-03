defmodule Charon.TokenPlugs.PutAssigns do
  @moduledoc """
  After verifying everything you would want to verify about a token,
  assign the following to the conn:
  - `:user_id` (bearer token claim "sub")
  - `:session_id` (bearer token claim "sid")
  - `:token_payload`
  - `:session` (if fetched with `Charon.TokenPlugs.load_session/2`)

  All of the assign names are overridable:

      # assign the user ID to key :current_user_id
      plug PutAssigns, claims: %{"sub" => :current_user_id, "sid" => :session_id}

  ## Doctests

      iex> opts = PutAssigns.init([])
      iex> conn = conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"})
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{session_id: "a", token_payload: %{"sid" => "a", "sub" => 1}, user_id: 1}

      iex> opts = PutAssigns.init(session: :da_session_baby)
      iex> conn = conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"}) |> set_session("hii")
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{
        session_id: "a",
        token_payload: %{"sid" => "a", "sub" => 1},
        user_id: 1,
        da_session_baby: "hii"
      }

      # skipped on auth error
      iex> opts = PutAssigns.init([])
      iex> conn = conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"}) |> Internal.auth_error("boom")
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{}
  """
  use Charon.Internal.Constants
  @behaviour Plug

  @defaults %{
    token_payload: :token_payload,
    session: :session,
    claims: %{
      "sub" => :user_id,
      "sid" => :session_id
    }
  }

  @impl true
  def init(opts) do
    overrides = Map.new(opts || %{})
    Map.merge(@defaults, overrides)
  end

  @impl true
  def call(conn = %{private: %{@auth_error => _}}, _), do: conn

  def call(conn = %{private: priv = %{@bearer_token_payload => token_payload}}, config) do
    config.claims
    |> Enum.reduce(conn.assigns, fn {claim_key, assign_key}, assigns ->
      assign_if_truthy(assigns, assign_key, Map.get(token_payload, claim_key))
    end)
    |> assign_if_truthy(config.session, Map.get(priv, @session))
    |> assign_if_truthy(config.token_payload, token_payload)
    |> then(&%{conn | assigns: &1})
  end

  def call(_, _), do: raise("must be used after verify_token_signature/2")

  defp assign_if_truthy(assigns, _key, nil), do: assigns
  defp assign_if_truthy(assigns, key, thing), do: Map.put(assigns, key, thing)
end
