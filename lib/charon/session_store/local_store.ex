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
  alias Charon.Internal
  require Logger

  def start_link(_) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @impl true
  def get(session_id, user_id, type, _config) do
    Agent.get(__MODULE__, fn state ->
      session = Map.get(state, {session_id, user_id, type}, nil)

      if session == nil || expired?(Internal.now(), session) do
        nil
      else
        session
      end
    end)
  end

  @impl true
  def upsert(
        session = %{
          id: session_id,
          user_id: user_id,
          type: type
        },
        _config
      ) do
    Agent.update(__MODULE__, fn state ->
      Map.put(state, {session_id, user_id, type}, session)
    end)
  end

  @impl true
  def delete(session_id, user_id, type, _config) do
    Agent.update(__MODULE__, fn state ->
      Map.drop(state, [{session_id, user_id, type}])
    end)
  end

  @impl true
  def get_all(user_id, type, _config) do
    now = Internal.now()

    Agent.get(__MODULE__, fn state ->
      state
      |> Stream.filter(&match?({{_, ^user_id, ^type}, _}, &1))
      |> Stream.reject(fn {_, v} -> expired?(now, v) end)
      |> Stream.map(fn {_, v} -> v end)
      |> Enum.to_list()
    end)
  end

  @impl true
  def delete_all(user_id, type, _config) do
    Agent.update(__MODULE__, fn state ->
      Map.reject(state, fn
        {{_, ^user_id, ^type}, _} -> true
        _ -> false
      end)
    end)
  end

  @doc """
  Deletes expired tokens from the agent.
  This should run periodically, for example once per day at a quiet moment.
  """
  @spec cleanup :: :ok
  def cleanup() do
    now = Internal.now()

    Agent.update(__MODULE__, fn state ->
      Map.reject(state, fn {_, v} -> expired?(now, v) end)
    end)
  end

  defp expired?(now, session) do
    now > session.refresh_expires_at
  end
end
