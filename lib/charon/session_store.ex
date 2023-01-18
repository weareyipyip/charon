defmodule Charon.SessionStore do
  @moduledoc """
  Entrypoint for `Charon.SessionStore.Behaviour` implementation.
  All functions delegate to the configured module.
  """
  @behaviour __MODULE__.Behaviour

  @impl true
  def delete(session_id, user_id, type, config),
    do: config.session_store_module.delete(session_id, user_id, type, config)

  @impl true
  def get(session_id, user_id, type, config),
    do: config.session_store_module.get(session_id, user_id, type, config)

  @impl true
  def get_all(user_id, type, config),
    do: config.session_store_module.get_all(user_id, type, config)

  @impl true
  def upsert(session, config), do: config.session_store_module.upsert(session, config)

  @impl true
  def delete_all(user_id, type, config),
    do: config.session_store_module.delete_all(user_id, type, config)

  @deprecated "use delete/4"
  def delete(session_id, user_id, config), do: delete(session_id, user_id, :full, config)

  @deprecated "use get/4"
  def get(session_id, user_id, config), do: get(session_id, user_id, :full, config)

  @deprecated "use get_all/3"
  def get_all(user_id, config), do: get_all(user_id, :full, config)

  @deprecated "use delete_all/3"
  def delete_all(user_id, config), do: delete_all(user_id, :full, config)
end
