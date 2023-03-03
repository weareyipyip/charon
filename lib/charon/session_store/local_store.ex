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

  def start_link(_opts \\ []), do: Agent.start_link(fn -> {0, %{}} end, name: @agent_name)

  @impl true
  def get(session_id, user_id, type, _config) do
    Agent.get(@agent_name, fn _state = {_count, store} ->
      session = Map.get(store, to_key(session_id, user_id, type))
      if is_nil(session) or expired?(session, now()), do: nil, else: session
    end)
  end

  @impl true
  def upsert(session, _config) do
    Agent.update(@agent_name, fn _state = {count, store} ->
      {count + 1, Map.put(store, to_key(session), session)} |> maybe_prune_expired()
    end)
  end

  @impl true
  def delete(session_id, user_id, type, _config) do
    Agent.update(@agent_name, fn _state = {count, store} ->
      {count - 1, Map.delete(store, to_key(session_id, user_id, type))}
    end)
  end

  @impl true
  def get_all(user_id, type, _config) do
    Agent.get(@agent_name, fn _state = {_count, store} ->
      store
      |> Stream.filter(match_user_and_type(user_id, type))
      |> Stream.reject(match_expired(now()))
      |> Enum.map(&value_only/1)
    end)
  end

  @impl true
  def delete_all(user_id, type, _config) do
    Agent.update(@agent_name, fn state ->
      delete_matching(state, match_user_and_type(user_id, type))
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

  defp key_only({k, _v}), do: k
  defp value_only({_k, v}), do: v

  defp delete_matching({count, store}, matcher) do
    keys = store |> Stream.filter(matcher) |> Enum.map(&key_only/1)
    {count - Enum.count(keys), Map.drop(store, keys)}
  end

  defp maybe_prune_expired(state = {count, _store}) when rem(count, 1000) == 0 do
    delete_matching(state, match_expired(now()))
  end

  defp maybe_prune_expired(state), do: state
end
