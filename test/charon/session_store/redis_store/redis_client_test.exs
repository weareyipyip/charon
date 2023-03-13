defmodule Charon.SessionStore.RedisStore.RedisClientTest do
  use ExUnit.Case
  alias Charon.SessionStore.RedisStore.{RedisClient, ConnectionPool}

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({ConnectionPool, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  describe "optimistic locking" do
    test "returns nil on conflict" do
      {:ok, _} = RedisClient.command(~w(set key value))
      conn_a = ConnectionPool.checkout()

      # setup optimistic_locking
      {:ok, _} = RedisClient.conn_pipeline(conn_a, [~w(watch key)])

      # mess it up
      {:ok, _} = RedisClient.command(~w(set key boom))

      # watch it burn
      assert {:ok, [_, _, nil]} =
               RedisClient.conn_pipeline(conn_a, [~w(multi), ~w(set key other_value), ~w(exec)])
    end

    test "works on no conflict" do
      {:ok, _} = RedisClient.command(~w(set key value))
      conn_a = ConnectionPool.checkout()

      # setup optimistic_locking
      {:ok, _} = RedisClient.conn_pipeline(conn_a, [~w(watch key)])

      assert {:ok, [_, _, ["OK"]]} =
               RedisClient.conn_pipeline(conn_a, [~w(multi), ~w(set key other_value), ~w(exec)])

      {:ok, "other_value"} = RedisClient.command(~w(get key))
    end
  end

  test "worker returns to pool on parent process death" do
    assert %{available_workers: 10} = ConnectionPool.status()

    fn ->
      _conn = ConnectionPool.checkout()
      assert %{available_workers: 9} = ConnectionPool.status()
      # this process forgets to return the worker to the pool, which is bad
    end
    |> Task.async()
    |> Task.await()

    assert %{available_workers: 10} = ConnectionPool.status()
  end
end
