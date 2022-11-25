defmodule Charon.SessionStore do
  @moduledoc """
  Entrypoint for `Charon.SessionStore.Behaviour` implementation.
  All functions delegate to the configured module.
  """
  @behaviour __MODULE__.Behaviour

  @impl true
  def delete(session_id, user_id, config),
    do: config.session_store_module.delete(session_id, user_id, config)

  @impl true
  def get(session_id, user_id, config),
    do: config.session_store_module.get(session_id, user_id, config)

  @impl true
  def get_all(user_id, config), do: config.session_store_module.get_all(user_id, config)

  @impl true
  def upsert(session, ttl, config), do: config.session_store_module.upsert(session, ttl, config)

  @impl true
  def delete_all(user_id, config), do: config.session_store_module.delete_all(user_id, config)
end
