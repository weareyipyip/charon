defmodule Charon.TokenPlugs.SigVerifyCache.EtsCacheTest do
  use ExUnit.Case, async: false
  alias Charon.TokenPlugs.SigVerifyCache.EtsCache

  @table EtsCache
  @config TestApp.Charon.get()

  setup do
    start_supervised!(EtsCache)
    :ok
  end

  describe "get/2" do
    test "returns :miss when key not found" do
      assert :miss = EtsCache.get(:crypto.hash(:sha256, "unknown_token"), @config)
    end

    test "returns {:hit, value} for a cached, non-expired success" do
      hash = :crypto.hash(:sha256, "my_token")
      value = {:ok, %{"sub" => 1}}
      EtsCache.put(hash, value, System.os_time(:second) + 3600, @config)

      assert {:hit, ^value} = EtsCache.get(hash, @config)
    end

    test "returns {:hit, value} for a cached, non-expired failure" do
      hash = :crypto.hash(:sha256, "invalid_token")
      value = {:error, "invalid signature"}
      EtsCache.put(hash, value, System.os_time(:second) + 3600, @config)

      assert {:hit, ^value} = EtsCache.get(hash, @config)
    end

    test "returns :miss for an expired entry" do
      hash = :crypto.hash(:sha256, "expired_token")
      EtsCache.put(hash, {:ok, %{"sub" => 1}}, System.os_time(:second) - 1, @config)

      assert :miss = EtsCache.get(hash, @config)
    end
  end

  describe "put/4" do
    test "stores a verification result keyed by token hash" do
      hash = :crypto.hash(:sha256, "some_token")
      value = {:ok, %{"sub" => 42}}
      exp = System.os_time(:second) + 600

      assert :ok = EtsCache.put(hash, value, exp, @config)
      assert {:hit, ^value} = EtsCache.get(hash, @config)
    end

    test "overwrites an existing entry" do
      hash = :crypto.hash(:sha256, "overwrite_token")
      exp = System.os_time(:second) + 600

      EtsCache.put(hash, {:ok, %{"sub" => 1}}, exp, @config)
      EtsCache.put(hash, {:ok, %{"sub" => 2}}, exp, @config)

      assert {:hit, {:ok, %{"sub" => 2}}} = EtsCache.get(hash, @config)
    end
  end

  describe "cleanup" do
    test "removes expired entries on cleanup message" do
      hash = :crypto.hash(:sha256, "cleanup_token")
      EtsCache.put(hash, {:ok, %{}}, System.os_time(:second) - 1, @config)

      # Trigger a cleanup manually by sending the message to the GenServer
      pid = Process.whereis(EtsCache)
      send(pid, :cleanup)
      # Allow the GenServer to process the message
      :sys.get_state(pid)

      assert :ets.lookup(@table, hash) == []
    end
  end
end
