defmodule Charon.SessionStore.DummyStore do
  @moduledoc """
  A dummy session store that can be used if fully stateless tokens are desired.
  """
  @behaviour Charon.SessionStore.Behaviour

  @impl true
  def get(_session_id, _user_id, _config), do: nil

  @impl true
  def upsert(_session, _config), do: :ok

  @impl true
  def delete(_session_id, _user_id, _config), do: :ok
end
