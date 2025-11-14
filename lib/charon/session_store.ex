defmodule Charon.SessionStore do
  @moduledoc """
  The persistent session store. See `Charon.SessionStore.Behaviour` for callbacks.
  All functions delegate to the configured session store module.

  Client applications should use this module to interact with the underlying implementation,
  because this module takes care of session struct version upgrades as well.
  """
  @behaviour __MODULE__.Behaviour
  alias Charon.Models.Session
  alias Charon.Telemetry

  @impl true
  def delete(session_id, user_id, type, config) do
    config.session_store_module.delete(session_id, user_id, type, config)
    |> emit_delete(session_id, user_id, type)
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
    config.session_store_module.upsert(session, config) |> emit_upsert(session)
  end

  @impl true
  def delete_all(user_id, type, config) do
    config.session_store_module.delete_all(user_id, type, config)
    |> emit_delete_all(user_id, type)
  end

  ###########
  # Private #
  ###########

  @compile {:inline, [emit_delete: 4, emit_upsert: 2, to_metadata: 1, emit_delete_all: 3]}

  defp emit_delete(:ok = res, id, uid, type) do
    %{session_id: id, user_id: uid, session_type: type} |> Telemetry.emit_session_delete()
    res
  end

  defp emit_delete(res, _, _, _), do: res

  defp emit_upsert(:ok = res, session) when session.created_at == session.refreshed_at do
    session |> to_metadata() |> Telemetry.emit_session_create()
    res
  end

  defp emit_upsert(:ok = res, session) do
    session |> to_metadata() |> Telemetry.emit_session_refresh()
    res
  end

  defp emit_upsert({:error, :conflict} = res, session) do
    session |> to_metadata() |> Telemetry.emit_session_lock_conflict()
    res
  end

  defp emit_upsert(res, _), do: res

  defp to_metadata(session) do
    %{session_id: session.id, user_id: session.user_id, session_type: session.type}
  end

  defp emit_delete_all(:ok = res, uid, type) do
    %{user_id: uid, session_type: type} |> Telemetry.emit_session_delete_all()
    res
  end

  defp emit_delete_all(res, _, _), do: res
end
