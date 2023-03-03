defmodule Charon.SessionStore.LocalStore do
  @moduledoc """
  An in-memory persistent session store, implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

  ## Usage

  Add this store to your supervision tree to use it.

      children = [
        Charon.SessionStore.LocalStore
      ]

  """
  use Agent
  @behaviour Charon.SessionStore.Behaviour

  import Charon.Internal
  require Logger

  @agent_name __MODULE__

  def start_link(_opts \\ []), do: Agent.start_link(fn -> %{} end, name: @agent_name)

  @impl true
  def get(session_id, user_id, type, _config) do
    Agent.get(@agent_name, fn state ->
      session = Map.get(state, to_key(session_id, user_id, type))
      if is_nil(session) or expired?(session, now()), do: nil, else: session
    end)
  end

  @impl true
  def upsert(session, _config) do
    Agent.update(@agent_name, fn state -> Map.put(state, to_key(session), session) end)
  end

  @impl true
  def delete(session_id, user_id, type, _config) do
    Agent.update(@agent_name, fn state -> Map.delete(state, to_key(session_id, user_id, type)) end)
  end

  @impl true
  def get_all(user_id, type, _config) do
    Agent.get(@agent_name, fn state ->
      state
      |> Stream.filter(match_user_and_type(user_id, type))
      |> Stream.reject(match_expired(now()))
      |> Enum.map(_extract_session = fn {_key, session} -> session end)
    end)
  end

  @impl true
  def delete_all(user_id, type, _config) do
    Agent.update(@agent_name, fn state ->
      state |> Stream.reject(match_user_and_type(user_id, type)) |> Map.new()
    end)
  end

  @doc """
  Deletes expired tokens from the agent.
  This should run periodically, for example once per day at a quiet moment.
  """
  @spec cleanup :: :ok
  def cleanup() do
    Agent.update(@agent_name, fn state ->
      state |> Stream.reject(match_expired(now())) |> Map.new()
    end)
  end

  ###########
  # Private #
  ###########

  defp expired?(session, now), do: now > session.refresh_expires_at

  defp to_key(%{id: sid, user_id: uid, type: type}), do: to_key(sid, uid, type)
  defp to_key(sid, uid, type), do: {sid, uid, type}

  defp match_user_and_type(uid, type), do: &match?({_key = {_, ^uid, ^type}, _session}, &1)

  defp match_expired(now), do: fn {_key, session} -> expired?(session, now) end
end
