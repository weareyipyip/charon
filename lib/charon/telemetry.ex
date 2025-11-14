defmodule Charon.Telemetry do
  @moduledoc since: "4.0.0"
  @moduledoc """
  Telemetry integration for Charon.

  Charon executes the following telemetry events:

  ## Session Events

  ### Session created

  Emitted when a new session is created.

  #### Event

      [:charon, :session, :create]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### Session refreshed

  Emitted when an existing session is refreshed.

  #### Event

      [:charon, :session, :refresh]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### Session deleted

  Emitted when a session is deleted.

  #### Event

      [:charon, :session, :delete]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ### All sessions deleted

  Emitted when all sessions for a user are deleted.

  #### Event

      [:charon, :session, :delete_all]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:user_id` - The user ID whose sessions are being deleted
    * `:session_type` - The type of sessions being deleted (e.g., `:full`, `:oauth2`)

  ### Session lock conflict

  Emitted when a session update fails due to an optimistic locking conflict.

  #### Event

      [:charon, :session, :lock_conflict]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_id` - The unique session identifier
    * `:user_id` - The user ID associated with the session
    * `:session_type` - The type of session (e.g., `:full`, `:oauth2`)

  ## Token Events

  ### Token valid

  Emitted when token verification succeeds. Note that this event is only emitted when `Charon.TokenPlugs.emit_telemetry/2` is called in your token verification pipeline.

  #### Event

      [:charon, :token, :valid]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_loaded` - Boolean indicating if a session was found
    * `:token_transport` - Atom indicating how the token was transmitted (`:bearer`, `:cookie`, or `:cookie_only`)
    * `:token_type` - The value of the `"type"` claim (e.g., `"access"` or `"refresh"`) - only present when token payload is available
    * `:user_id` - The value of the `"sub"` claim - only present when token payload is available
    * `:session_id` - The value of the `"sid"` claim - only present when token payload is available
    * `:session_type` - The value of the `"styp"` claim - only present when token payload is available

  ### Token invalid

  Emitted when token verification fails. Note that this event is only emitted when `Charon.TokenPlugs.emit_telemetry/2` is called in your token verification pipeline.

  #### Event

      [:charon, :token, :invalid]

  #### Measurements

    * `:count` - Always 1

  #### Metadata

    * `:session_loaded` - Boolean indicating if a session was found
    * `:token_transport` - Atom indicating how the token was transmitted (`:bearer`, `:cookie`, or `:cookie_only`)
    * `:error` - The error message string describing why verification failed
    * `:token_type` - The value of the `"type"` claim (e.g., `"access"` or `"refresh"`) - only present when token payload is available
    * `:user_id` - The value of the `"sub"` claim - only present when token payload is available
    * `:session_id` - The value of the `"sid"` claim - only present when token payload is available
    * `:session_type` - The value of the `"styp"` claim - only present when token payload is available

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
            counter("charon.session.delete_all.count"),
            counter("charon.session.lock_conflict.count"),
            counter("charon.token.valid.count"),
            counter("charon.token.invalid.count")
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

  @doc false
  # Emits a telemetry event for session lock conflicts.
  def emit_session_lock_conflict(metadata) do
    :telemetry.execute([:charon, :session, :lock_conflict], %{count: 1}, metadata)
  end

  @doc false
  # Emits a telemetry event for a validated token
  def emit_token_valid(metadata) do
    :telemetry.execute([:charon, :token, :valid], %{count: 1}, metadata)
  end

  @doc false
  # Emits a telemetry event for an invalid token
  def emit_token_invalid(metadata) do
    :telemetry.execute([:charon, :token, :invalid], %{count: 1}, metadata)
  end
end
