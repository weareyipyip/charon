defmodule Charon.TelemetryTest do
  use ExUnit.Case
  @moduletag :capture_log
  use Charon.Internal.Constants

  alias Charon.{SessionPlugs, Utils}
  alias Plug.Conn
  import Charon.TestUtils

  @config TestApp.Charon.get()

  def telemetry_handler(event_name, measurements, metadata, _config) do
    send(self(), {:telemetry, event_name, measurements, metadata})
  end

  setup do
    start_supervised!(Charon.SessionStore.LocalStore)

    # Subscribe to all Charon telemetry events
    :telemetry.attach_many(
      "test-handler",
      [
        [:charon, :session, :create],
        [:charon, :session, :refresh],
        [:charon, :session, :delete],
        [:charon, :session, :delete_all],
        [:charon, :session, :lock_conflict],
        [:charon, :token, :valid],
        [:charon, :token, :invalid]
      ],
      &__MODULE__.telemetry_handler/4,
      nil
    )

    on_exit(fn -> :telemetry.detach("test-handler") end)
  end

  describe "session create telemetry" do
    test "should emit create event when creating a new session" do
      conn =
        conn()
        |> SessionPlugs.upsert_session(@config, user_id: 1, token_transport: :bearer)

      session = Utils.get_session(conn)

      assert_receive {:telemetry, [:charon, :session, :create], measurements, metadata}
      assert measurements == %{count: 1}
      assert metadata.session_id == session.id
      assert metadata.user_id == 1
      assert metadata.session_type == :full
    end

    test "should include session_type in telemetry metadata" do
      conn()
      |> SessionPlugs.upsert_session(@config,
        user_id: 42,
        token_transport: :cookie,
        session_type: :oauth2
      )

      assert_receive {:telemetry, [:charon, :session, :create], _measurements, metadata}
      assert metadata.user_id == 42
      assert metadata.session_type == :oauth2
    end
  end

  describe "session refresh telemetry" do
    test "should emit refresh event when refreshing an existing session" do
      session = test_session(user_id: 1, id: "test-session", created_at: 1)

      conn()
      |> Conn.put_private(@session, session)
      |> SessionPlugs.upsert_session(@config, user_id: 1, token_transport: :bearer)

      assert_receive {:telemetry, [:charon, :session, :refresh], measurements, metadata}
      assert measurements == %{count: 1}
      assert metadata.session_id == "test-session"
      assert metadata.user_id == 1
      assert metadata.session_type == :full
    end
  end

  describe "session delete telemetry" do
    test "should emit delete event when deleting a session" do
      # Create and store a session
      session = test_session(user_id: 1, id: "test-session")
      Charon.SessionStore.upsert(session, @config)

      conn()
      |> Plug.Conn.put_private(@bearer_token_payload, %{
        "sub" => session.user_id,
        "sid" => session.id,
        "styp" => "full"
      })
      |> SessionPlugs.delete_session(@config)

      assert_receive {:telemetry, [:charon, :session, :delete], measurements, metadata}
      assert measurements == %{count: 1}
      assert metadata.session_id == session.id
      assert metadata.user_id == 1
      assert metadata.session_type == :full
    end

    test "should not emit delete event when no session exists" do
      conn()
      |> SessionPlugs.delete_session(@config)

      refute_receive {:telemetry, [:charon, :session, :delete], _, _}, 100
    end
  end

  describe "session delete_all telemetry" do
    test "should emit delete_all event when deleting all sessions" do
      Charon.SessionStore.delete_all(123, :full, @config)

      assert_receive {:telemetry, [:charon, :session, :delete_all], measurements, metadata}
      assert measurements == %{count: 1}
      assert metadata.user_id == 123
      assert metadata.session_type == :full
    end
  end

  describe "session lock_conflict telemetry" do
    test "should emit lock_conflict event when session update conflicts" do
      # Create a session with lock_version 0
      session = test_session(user_id: 1, id: "test-session", lock_version: 0)

      # Store it (this increments lock_version to 1 in the store)
      assert :ok = Charon.SessionStore.upsert(session, @config)

      # Clear the create event from mailbox
      assert_receive {:telemetry, [:charon, :session, :create], _, _}

      # Try to upsert the same session with outdated lock_version (0)
      # This should cause a conflict and emit the lock_conflict event
      assert {:error, :conflict} = Charon.SessionStore.upsert(session, @config)

      assert_receive {:telemetry, [:charon, :session, :lock_conflict], measurements, metadata}
      assert measurements == %{count: 1}
      assert metadata.session_id == "test-session"
      assert metadata.user_id == 1
      assert metadata.session_type == :full
    end
  end

  describe "telemetry module functions" do
    test "emit_session_create/1 executes telemetry event" do
      metadata = %{
        session_id: "test-session-id",
        user_id: 123,
        session_type: :full,
        token_transport: :bearer
      }

      Charon.Telemetry.emit_session_create(metadata)

      assert_receive {:telemetry, [:charon, :session, :create], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_session_refresh/1 executes telemetry event" do
      metadata = %{
        session_id: "test-session-id",
        user_id: 456,
        session_type: :oauth2,
        token_transport: :cookie
      }

      Charon.Telemetry.emit_session_refresh(metadata)

      assert_receive {:telemetry, [:charon, :session, :refresh], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_session_delete/1 executes telemetry event" do
      metadata = %{
        session_id: "test-session-id",
        user_id: 789,
        session_type: :full
      }

      Charon.Telemetry.emit_session_delete(metadata)

      assert_receive {:telemetry, [:charon, :session, :delete], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_session_delete_all/1 executes telemetry event" do
      metadata = %{
        user_id: 456,
        session_type: :oauth2
      }

      Charon.Telemetry.emit_session_delete_all(metadata)

      assert_receive {:telemetry, [:charon, :session, :delete_all], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_session_lock_conflict/1 executes telemetry event" do
      metadata = %{
        session_id: "test-session-id",
        user_id: 123,
        session_type: :full
      }

      Charon.Telemetry.emit_session_lock_conflict(metadata)

      assert_receive {:telemetry, [:charon, :session, :lock_conflict], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_token_valid/1 executes telemetry event with minimal metadata" do
      metadata = %{
        session_loaded: false,
        token_transport: :bearer
      }

      Charon.Telemetry.emit_token_valid(metadata)

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_token_valid/1 executes telemetry event with full metadata" do
      metadata = %{
        session_loaded: true,
        token_transport: :cookie,
        token_type: "access",
        user_id: 123,
        session_id: "test-session-id",
        session_type: "full"
      }

      Charon.Telemetry.emit_token_valid(metadata)

      assert_receive {:telemetry, [:charon, :token, :valid], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_token_invalid/1 executes telemetry event with error" do
      metadata = %{
        session_loaded: false,
        token_transport: :bearer,
        error: "bearer token signature invalid"
      }

      Charon.Telemetry.emit_token_invalid(metadata)

      assert_receive {:telemetry, [:charon, :token, :invalid], measurements, ^metadata}
      assert measurements == %{count: 1}
    end

    test "emit_token_invalid/1 executes telemetry event with full metadata" do
      metadata = %{
        session_loaded: true,
        token_transport: :cookie_only,
        error: "bearer token expired",
        token_type: "refresh",
        user_id: 456,
        session_id: "expired-session-id",
        session_type: "oauth2"
      }

      Charon.Telemetry.emit_token_invalid(metadata)

      assert_receive {:telemetry, [:charon, :token, :invalid], measurements, ^metadata}
      assert measurements == %{count: 1}
    end
  end
end
