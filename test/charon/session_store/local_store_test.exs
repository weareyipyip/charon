defmodule Charon.SessionStore.LocalStoreTest do
  use ExUnit.Case
  alias Charon.SessionStore.LocalStore
  import Charon.{TestUtils, Internal}

  @ttl 10
  @exp now() + @ttl
  @sid "a"
  @uid 426
  @stype :full
  @config %{}
  @user_key {@sid, @uid, @stype}
  @user_session test_session(id: @sid, user_id: @uid, refresh_expires_at: @exp)
  @lock_incr_user_session %{@user_session | lock_version: 1}

  defp incr_lock(s = %{lock_version: l}), do: %{s | lock_version: l + 1}

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
      Agent.update(LocalStore, fn _ -> {1, %{@user_key => expired_session}} end)
      assert nil == LocalStore.get(@sid, @uid, @stype, @config)
    end

    test "returns nil if other type" do
      Agent.update(LocalStore, fn _ -> {1, %{@user_key => @user_session}} end)
      assert nil == LocalStore.get(@sid, @uid, :invalid_type, @config)
    end

    test "returns session" do
      Agent.update(LocalStore, fn _ -> {1, %{@user_key => @user_session}} end)
      assert @user_session == LocalStore.get(@sid, @uid, @stype, @config)
    end
  end

  describe "upsert/3" do
    test "stores session by session id, user id and type" do
      assert :ok = LocalStore.upsert(@user_session, @config)
      assert {1, %{@user_key => @lock_incr_user_session}} == Agent.get(LocalStore, & &1)
    end

    test "seperates sessions by type" do
      other_type_session = %{@user_session | type: :other_type}
      assert :ok = LocalStore.upsert(@user_session, @config)
      assert :ok = LocalStore.upsert(other_type_session, @config)

      assert {2,
              %{
                @user_key => @lock_incr_user_session,
                {@sid, @uid, :other_type} => incr_lock(other_type_session)
              }} == Agent.get(LocalStore, & &1)
    end

    test "updates existing session" do
      assert :ok = LocalStore.upsert(@user_session, @config)
      current_session = @lock_incr_user_session
      assert {1, %{@user_key => current_session}} == Agent.get(LocalStore, & &1)
      updated_user_sessioin = %{current_session | refresh_expires_at: @exp + 1}
      assert :ok = LocalStore.upsert(updated_user_sessioin, @config)
      assert {2, %{@user_key => incr_lock(updated_user_sessioin)}} == Agent.get(LocalStore, & &1)
    end

    test "cleans up expired sessions when session count is multiple of 1000" do
      exp = now() - 10

      for n <- 1..999 do
        assert :ok = LocalStore.upsert(%{@user_session | id: n, refresh_expires_at: exp}, @config)
      end

      assert {999, store} = Agent.get(LocalStore, & &1)
      assert 999 = Enum.count(store)

      only_valid_session = %{@user_session | id: 1000}
      assert :ok = LocalStore.upsert(only_valid_session, @config)
      only_valid_session = incr_lock(only_valid_session)
      assert {1, %{{1000, 426, :full} => ^only_valid_session}} = Agent.get(LocalStore, & &1)
    end

    test "implements optimistic locking" do
      assert :ok = LocalStore.upsert(@user_session, @config)
      # stored lock_version has been increased
      assert {:error, :conflict} = LocalStore.upsert(@user_session, @config)
    end
  end

  describe "delete/4" do
    test "returns ok if session not found" do
      assert :error = LocalStore.delete(@sid, @uid, @stype, @config)
      assert {0, _} = Agent.get(LocalStore, & &1)
    end

    test "deletes session" do
      Agent.update(LocalStore, fn _ -> {1, %{@user_key => @user_session}} end)
      assert :ok = LocalStore.delete(@sid, @uid, @stype, @config)
      assert {0, %{}} == Agent.get(LocalStore, & &1)
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
        {2,
         %{
           @user_key => @user_session,
           second_key => second_session,
           expired_key => expired_session
         }}
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
      second_user_session = %{@user_session | user_id: @uid + 1}
      second_user_key = {@sid, @uid + 1, @stype}

      Agent.update(LocalStore, fn _ ->
        {3,
         %{
           @user_key => @user_session,
           second_key => second_session,
           second_user_key => second_user_session
         }}
      end)

      assert :ok = LocalStore.delete_all(@uid, @stype, @config)

      assert {1, %{second_user_key => second_user_session}} == Agent.get(LocalStore, & &1)
    end
  end
end
