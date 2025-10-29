defmodule Charon.SessionStore do
  @moduledoc """
  The persistent session store. See `Charon.SessionStore.Behaviour` for callbacks.
  All functions delegate to the configured session store module.

  Client applications should use this module to interact with the underlying implementation,
  because this module takes care of session struct version upgrades and telemetry events,
  in addition to dispatching to the implementation module.
  """
  @behaviour __MODULE__.Behaviour
  alias Charon.Models.Session
  alias Charon.Telemetry

  @impl true
  def delete(session_id, user_id, type, config) do
    config.session_store_module.delete(session_id, user_id, type, config)
    |> tap(fn
      :ok ->
        %{session_id: session_id, user_id: user_id, session_type: type}
        |> Telemetry.emit_session_delete()

      _ ->
        :ok
    end)
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
      sessions when is_list(sessions) -> for s <- sessions, do: Session.upgrade_version(s, config)
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
    |> tap(fn
      :ok -> Telemetry.emit_session_delete_all(%{user_id: user_id, session_type: type})
      _ -> :ok
    end)
  end

  @doc false
  def generate(base_mod) do
    quote generated: true,
          location: :keep,
          bind_quoted: [
            base_mod: base_mod,
            module_name: Module.concat(base_mod, SessionStore),
            moddoc: @moduledoc
          ] do
      defmodule module_name do
        @moduledoc moddoc
        @behaviour Charon.SessionStore.Behaviour

        @impl true
        defdelegate delete(session_id, user_id, type, config \\ unquote(base_mod).get_config()),
          to: Charon.SessionStore

        @impl true
        defdelegate get(session_id, user_id, type, config \\ unquote(base_mod).get_config()),
          to: Charon.SessionStore

        @impl true
        defdelegate upsert(session, config \\ unquote(base_mod).get_config()),
          to: Charon.SessionStore

        @impl true
        defdelegate get_all(user_id, type, config \\ unquote(base_mod).get_config()),
          to: Charon.SessionStore

        @impl true
        defdelegate delete_all(user_id, type, config \\ unquote(base_mod).get_config()),
          to: Charon.SessionStore
      end
    end
    |> Code.compile_quoted()
  end
end
