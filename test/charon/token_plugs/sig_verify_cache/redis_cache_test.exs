defmodule Charon.TokenPlugs.SigVerifyCache.RedisCacheTest do
  use ExUnit.Case, async: false
  alias Charon.TokenPlugs.SigVerifyCache.RedisCache
  alias Charon.SessionStore.RedisStore.{ConnectionPool, RedisClient}

  @config TestApp.Charon.get()

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost"), database: 15]
    start_supervised!({ConnectionPool, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  describe "get/2" do
    test "returns :miss when key not found" do
      assert :miss = RedisCache.get(:crypto.hash(:sha256, "unknown_token"), @config)
    end

    test "returns {:hit, value} for a cached, non-expired success" do
      hash = :crypto.hash(:sha256, "my_token")
      value = {:ok, %{"sub" => 1}}
      RedisCache.put(hash, value, System.os_time(:second) + 3600, @config)

      assert {:hit, ^value} = RedisCache.get(hash, @config)
    end

    test "returns {:hit, value} for a cached, non-expired failure" do
      hash = :crypto.hash(:sha256, "invalid_token")
      value = {:error, "invalid signature"}
      RedisCache.put(hash, value, System.os_time(:second) + 3600, @config)

      assert {:hit, ^value} = RedisCache.get(hash, @config)
    end

    test "returns :miss for an expired entry" do
      hash = :crypto.hash(:sha256, "expired_token")
      # exp in the past — Redis will immediately treat the key as expired/gone
      RedisCache.put(hash, {:ok, %{"sub" => 1}}, System.os_time(:second) - 1, @config)

      assert :miss = RedisCache.get(hash, @config)
    end
  end

  describe "put/4" do
    test "stores a verification result keyed by token hash" do
      hash = :crypto.hash(:sha256, "some_token")
      value = {:ok, %{"sub" => 42}}

      assert :ok = RedisCache.put(hash, value, System.os_time(:second) + 600, @config)
      assert {:hit, ^value} = RedisCache.get(hash, @config)
    end

    test "overwrites an existing entry" do
      hash = :crypto.hash(:sha256, "overwrite_token")
      exp = System.os_time(:second) + 600

      RedisCache.put(hash, {:ok, %{"sub" => 1}}, exp, @config)
      RedisCache.put(hash, {:ok, %{"sub" => 2}}, exp, @config)

      assert {:hit, {:ok, %{"sub" => 2}}} = RedisCache.get(hash, @config)
    end
  end
end
