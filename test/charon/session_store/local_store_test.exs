defmodule Charon.SessionStore.LocalStoreTest do
  use ExUnit.Case
  alias Charon.SessionStore.LocalStore
  alias Charon.Models.Session
  import Charon.{TestUtils, Internal}

  @ttl 10
  @exp now() + @ttl
  @sid "a"
  @uid 426
  @stype :full
  @config %{}
  @user_key {@sid, @uid, @stype}
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: @exp)

  setup do
    start_supervised!(LocalStore)
    :ok
  end

  describe "get/4" do
    test "returns nil if session not found" do
      assert nil == LocalStore.get(@sid, @uid, @stype, @config)
    end

    test "returns nil if session expired" do
      expired_session = %{@user_session | refresh_expires_at: 0}
      Agent.update(LocalStore, fn _ -> %{@user_key => expired_session} end)
      assert nil == LocalStore.get(@sid, @uid, @stype, @config)
    end

    test "returns nil if other type" do
      Agent.update(LocalStore, fn _ -> %{@user_key => @user_session} end)
      assert nil == LocalStore.get(@sid, @uid, :invalid_type, @config)
    end

    test "returns session" do
      Agent.update(LocalStore, fn _ -> %{@user_key => @user_session} end)
      assert @user_session == LocalStore.get(@sid, @uid, @stype, @config)
    end
  end

  describe "upsert/3" do
    test "stores session by session id, user id and type" do
      assert :ok = LocalStore.upsert(@user_session, @config)
      assert %{@user_key => @user_session} == Agent.get(LocalStore, fn state -> state end)
    end

    test "seperates sessions by type" do
      other_type_session = %{@user_session | type: :other_type}
      assert :ok = LocalStore.upsert(@user_session, @config)
      assert :ok = LocalStore.upsert(other_type_session, @config)

      assert %{
               @user_key => @user_session,
               {@sid, @uid, :other_type} => other_type_session
             } == Agent.get(LocalStore, fn state -> state end)
    end

    test "updates existing session" do
      assert :ok = LocalStore.upsert(@user_session, @config)
      assert %{@user_key => @user_session} == Agent.get(LocalStore, fn state -> state end)
      new_user_session = %{@user_session | refresh_expires_at: @exp + 1}
      assert :ok = LocalStore.upsert(new_user_session, @config)
      assert %{@user_key => new_user_session} == Agent.get(LocalStore, fn state -> state end)
    end
  end

  describe "delete/4" do
    test "returns ok if session not found" do
      assert :ok = LocalStore.delete(@sid, @uid, @stype, @config)
    end

    test "deletes session" do
      Agent.update(LocalStore, fn _ -> %{@user_key => @user_session} end)
      assert :ok = LocalStore.delete(@sid, @uid, @stype, @config)
      assert %{} == Agent.get(LocalStore, fn state -> state end)
    end
  end

  describe "get_all/3" do
    test "returns empty list when user has no sessions" do
      assert [] == LocalStore.get_all(@uid, @stype, @config)
    end

    test "returns all of user's unexpired sessions with requested type" do
      second_session = %{@user_session | id: "b"}
      second_key = {"b", @uid, @stype}
      expired_session = %{@user_session | refresh_expires_at: 0, id: "c"}
      expired_key = {"c", @uid, @stype}

      Agent.update(LocalStore, fn _ ->
        %{
          @user_key => @user_session,
          second_key => second_session,
          expired_key => expired_session
        }
      end)

      assert [@user_session, second_session] == LocalStore.get_all(@uid, @stype, @config)
    end
  end

  describe "delete_all/3" do
    test "returns ok when user has no sessions" do
      assert :ok = LocalStore.delete_all(@uid, @stype, @config)
    end

    test "removes all of user's sessions with requested type" do
      second_session = %{@user_session | id: "b"}
      second_key = {"b", @uid, @stype}

      Agent.update(LocalStore, fn _ ->
        %{
          @user_key => @user_session,
          second_key => second_session
        }
      end)

      assert :ok = LocalStore.delete_all(@uid, @stype, @config)
      assert %{} == Agent.get(LocalStore, fn state -> state end)
    end
  end

  describe "cleanup/0" do
    test "removes all expired sessions" do
      expired_session = %{@user_session | refresh_expires_at: 0, id: "b"}
      expired_key = {"b", @uid, @stype}

      second_expired_session = %{
        @user_session
        | refresh_expires_at: 0,
          user_id: @uid + 1,
          id: "c"
      }

      second_expired_key = {"c", @uid + 1, @stype}

      Agent.update(LocalStore, fn _ ->
        %{
          @user_key => @user_session,
          expired_key => expired_session,
          second_expired_key => second_expired_session
        }
      end)

      LocalStore.cleanup()
      assert %{@user_key => @user_session} == Agent.get(LocalStore, fn state -> state end)
    end
  end
end
