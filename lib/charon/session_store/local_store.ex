defmodule Charon.SessionStore.LocalStore do
  @moduledoc """
  An in-memory persistent session store, implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

  Add this store to your supervision tree to use it.
  """
  use Agent

  @behaviour Charon.SessionStore.Behaviour
  alias Charon.Internal
  alias Charon.Models.Session
  require Logger

  def start_link(_) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @impl true
  def get(session_id, user_id, type, _config) do
    Agent.get(__MODULE__, fn state ->
      session = Map.get(state, {session_id, user_id, type}, nil)

      if session == nil || Internal.now() > session.refresh_expires_at do
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
      |> Stream.filter(fn
        {{_, ^user_id, ^type}, %{refresh_expires_at: exp}} when exp > now -> true
        _ -> false
      end)
      |> Stream.map(fn {_, v} -> v end)
      |> Enum.to_list()
    end)
  end

  @impl true
  def delete_all(user_id, type, _config) do
    Agent.update(__MODULE__, fn state ->
      user_session_keys =
        state
        |> Map.keys()
        |> Enum.filter(fn {_, state_uid, state_type} ->
          {user_id, type} == {state_uid, state_type}
        end)

      Map.drop(state, user_session_keys)
    end)
  end

  def cleanup() do
    now = Internal.now()
    Agent.update(__MODULE__, fn state ->
      Map.filter(state, fn {_, session} ->
        session.refresh_expires_at > now
      end)
    end)
  end

  # helpers
  def insert_ses(sid, uid, expiration \\ 100_000) do
    %Session{
      created_at: Internal.now(),
      expires_at: 0,
      id: sid,
      user_id: uid,
      refresh_expires_at: Internal.now() + expiration,
      refresh_token_id: <<0>>,
      t_gen_fresh_at: 0,
      refreshed_at: 0
    }
    |> upsert(%{})
  end

  def get_full() do
    Agent.get(__MODULE__, fn state -> state end)
  end

end
