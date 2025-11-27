defmodule Charon.TokenFactory.Jwt.OtkCacheTest do
  use ExUnit.Case, async: true
  import Charon.Internal
  alias Charon.TokenFactory.Jwt.OtkCache

  setup_all do
    # Start a fresh cache for each test
    {:ok, pid} = start_supervised({OtkCache, name: __MODULE__, prune_interval: :timer.minutes(1)})

    %{pid: pid}
  end

  setup do
    :ets.delete_all_objects(__MODULE__)
    []
  end

  describe "start_link/1" do
    test "starts with default options" do
      assert {:ok, pid} = OtkCache.start_link(name: :default_cache, table: :default_table)
      assert Process.alive?(pid)
      # Verify ETS table was created
      assert :ets.info(:default_table) != :undefined
      GenServer.stop(pid)
    end

    test "starts with custom prune_interval" do
      opts = [
        name: :custom_cache,
        table: :custom_table,
        prune_interval: :timer.minutes(30)
      ]

      assert {:ok, pid} = OtkCache.start_link(opts)
      assert Process.alive?(pid)
      GenServer.stop(pid)
    end

    test "creates ETS table with configured options" do
      opts = [
        name: :opts_cache,
        table: :opts_table,
        table_opts: [:set, :public, :named_table]
      ]

      assert {:ok, pid} = OtkCache.start_link(opts)
      info = :ets.info(:opts_table)
      assert info[:type] == :set
      assert info[:protection] == :public
      assert info[:named_table] == true
      GenServer.stop(pid)
    end
  end

  describe "put/4" do
    test "stores a value with expiration" do
      key = "test_key"
      value = :crypto.strong_rand_bytes(32)
      exp = now() + 3600

      assert true == OtkCache.put(__MODULE__, key, value, exp)

      # Verify it's stored in ETS
      assert [{^key, {^exp, ^value}}] = :ets.lookup(__MODULE__, key)
    end
  end

  describe "get/2" do
    test "retrieves stored value" do
      key = "test_key"
      value = :crypto.strong_rand_bytes(32)
      exp = now() + 3600

      OtkCache.put(__MODULE__, key, value, exp)
      assert ^value = OtkCache.get(__MODULE__, key)
    end

    test "returns nil for nonexistent key" do
      assert nil == OtkCache.get(__MODULE__, "nonexistent")
    end

    test "returns expired values until pruned" do
      key = "expired_key"
      value = :crypto.strong_rand_bytes(32)
      exp = now() - 10

      OtkCache.put(__MODULE__, key, value, exp)

      # Still retrievable before pruning
      assert ^value = OtkCache.get(__MODULE__, key)

      # After pruning, it should be gone
      OtkCache.prune_now(__MODULE__)
      assert nil == OtkCache.get(__MODULE__, key)
    end
  end

  describe "prune_now/1" do
    test "removes expired entries" do
      exp_past = now() - 10
      exp_future = now() + 3600

      OtkCache.put(__MODULE__, "expired1", <<1>>, exp_past)
      OtkCache.put(__MODULE__, "expired2", <<2>>, exp_past)
      OtkCache.put(__MODULE__, "valid1", <<3>>, exp_future)
      OtkCache.put(__MODULE__, "valid2", <<4>>, exp_future)

      count = OtkCache.prune_now(__MODULE__)
      assert count == 2

      # Verify expired entries are gone
      assert nil == OtkCache.get(__MODULE__, "expired1")
      assert nil == OtkCache.get(__MODULE__, "expired2")

      # Verify valid entries remain
      assert <<3>> = OtkCache.get(__MODULE__, "valid1")
      assert <<4>> = OtkCache.get(__MODULE__, "valid2")
    end
  end

  describe "automatic pruning" do
    test "prunes expired entries automatically" do
      start_supervised!({OtkCache, name: :fast_pruner, table: :fast_pruner, prune_interval: 10})

      exp_past = now() - 10
      exp_future = now() + 3600

      OtkCache.put(:fast_pruner, "expired", <<1>>, exp_past)
      OtkCache.put(:fast_pruner, "valid", <<2>>, exp_future)

      # Wait for automatic pruning
      Process.sleep(20)

      # Expired entry should be gone
      assert nil == OtkCache.get(:fast_pruner, "expired")
      # Valid entry should remain
      assert <<2>> = OtkCache.get(:fast_pruner, "valid")
    end
  end
end
