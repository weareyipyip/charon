defmodule Charon.Telemetry do
  @moduledoc """
  Telemetry integration for Charon.

  Charon executes the following telemetry events:

  ## Session Events

  ### `[:charon, :session, :create]`

  Executed when a new session is created.

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### `[:charon, :session, :refresh]`

  Executed when an existing session is refreshed.

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### `[:charon, :session, :delete]`

  Executed when a session is deleted.

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### `[:charon, :session, :delete_all]`

  Executed when all sessions for a user are deleted.

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:user_id` - The user ID whose sessions are being deleted
    * `:session_type` - The type of sessions being deleted (e.g., `:full`, `:oauth2`)

  ## Example Usage

  You can attach to these events using `:telemetry.attach/4` or `:telemetry.attach_many/4`:

      :telemetry.attach(
        "charon-session-handler",
        [:charon, :session, :create],
        &MyApp.Telemetry.handle_event/4,
        nil
      )

  Or use `Telemetry.Metrics` to define metrics:

      defmodule MyApp.Telemetry do
        import Telemetry.Metrics

        def metrics do
          [
            counter("charon.session.create.count"),
            counter("charon.session.refresh.count"),
            counter("charon.session.delete.count"),
            counter("charon.session.delete_all.count")
          ]
        end
      end
  """

  @doc false
  # Emits a telemetry event for session creation
  def emit_session_create(metadata) do
    :telemetry.execute([:charon, :session, :create], %{count: 1}, metadata)
  end

  @doc false
  # Emits a telemetry event for session refresh.
  def emit_session_refresh(metadata) do
    :telemetry.execute([:charon, :session, :refresh], %{count: 1}, metadata)
  end

  @doc false
  # Emits a telemetry event for session deletion.
  def emit_session_delete(metadata) do
    :telemetry.execute([:charon, :session, :delete], %{count: 1}, metadata)
  end

  @doc false
  # Emits a telemetry event for bulk session deletion.
  def emit_session_delete_all(metadata) do
    :telemetry.execute([:charon, :session, :delete_all], %{count: 1}, metadata)
  end
end
