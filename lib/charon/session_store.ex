defmodule Charon.SessionStore do
  @moduledoc """
  The persistent session store. See `Charon.SessionStore.Behaviour` for callbacks.
  All functions delegate to the configured session store module.

  Client applications should use this module to interact with the underlying implementation,
  because this module takes care of session struct version upgrades as well.
  """
  @behaviour __MODULE__.Behaviour
  alias Charon.Models.Session

  @impl true
  def delete(session_id, user_id, type, config) do
    config.session_store_module.delete(session_id, user_id, type, config)
  end

  @impl true
  def get(session_id, user_id, type, config) do
    config.session_store_module.get(session_id, user_id, type, config)
    |> case do
      session = %{} -> Session.upgrade_version(session, config)
      other -> other
    end
  end

  @impl true
  def get_all(user_id, type, config) do
    config.session_store_module.get_all(user_id, type, config)
    |> case do
      sessions when is_list(sessions) -> Enum.map(sessions, &Session.upgrade_version(&1, config))
      other -> other
    end
  end

  @impl true
  def upsert(session, config) do
    config.session_store_module.upsert(session, config)
  end

  @impl true
  def delete_all(user_id, type, config) do
    config.session_store_module.delete_all(user_id, type, config)
  end
end
