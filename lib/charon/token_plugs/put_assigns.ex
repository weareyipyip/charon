defmodule Charon.TokenPlugs.PutAssigns do
  @moduledoc """
  After verifying everything you would want to verify about a token,
  assign the following to the conn:
  - `:user_id`
  - `:session_id`
  - `:token_payload`
  - `:session` (if fetched with `Charon.TokenPlugs.load_session/2`)

  All of the assign names are overridable:

      # assign the user ID to key :current_user_id
      plug PutAssigns, user_id: :current_user_id

  ## Doctests

      iex> opts = PutAssigns.init([])
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"sub" => 1, "sid" => "a"})
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{session_id: "a", token_payload: %{"sid" => "a", "sub" => 1}, user_id: 1}

      iex> opts = PutAssigns.init(session: :da_session_baby)
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"sub" => 1, "sid" => "a"}) |> put_private(@session, "hii")
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{
        session_id: "a",
        token_payload: %{"sid" => "a", "sub" => 1},
        user_id: 1,
        da_session_baby: "hii"
      }

      # skipped on auth error
      iex> opts = PutAssigns.init([])
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"sub" => 1, "sid" => "a"}) |> Internal.auth_error("boom")
      iex> conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      %{}
  """
  use Charon.Constants
  @behaviour Plug

  @default_names %{
    user_id: :user_id,
    session_id: :session_id,
    token_payload: :token_payload,
    session: :session
  }

  @impl true
  def init(opts) do
    overrides = Map.new(opts || %{})
    Map.merge(@default_names, overrides)
  end

  @impl true
  def call(conn = %{private: %{@auth_error => _}}, _), do: conn

  def call(
        conn = %{private: priv = %{@bearer_token_payload => token_payload}},
        assign_names
      ) do
    %{"sub" => uid, "sid" => sid} = token_payload

    %{
      user_id: uid,
      session_id: sid,
      token_payload: token_payload,
      session: Map.get(priv, @session)
    }
    |> Enum.reduce(conn.assigns, fn
      {_default_name, nil}, assigns -> assigns
      {default_name, v}, assigns -> Map.put(assigns, Map.get(assign_names, default_name), v)
    end)
    |> then(&%{conn | assigns: &1})
  end

  def call(_, _), do: raise("must be used after verify_token_signature/2")
end
