defmodule Charon.SessionStore.RedisStore.RedisClientTest do
  use ExUnit.Case
  alias Charon.SessionStore.RedisStore.{RedisClient, ConnectionPool}

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost"), database: 15]
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
      {:ok, _} = RedisClient.conn_pipeline([~w(watch key)], conn_a)

      # mess it up
      {:ok, _} = RedisClient.command(~w(set key boom))

      # watch it burn
      assert {:ok, [_, _, nil]} =
               RedisClient.conn_pipeline([~w(multi), ~w(set key other_value), ~w(exec)], conn_a)
    end

    test "works on no conflict" do
      {:ok, _} = RedisClient.command(~w(set key value))
      conn_a = ConnectionPool.checkout()

      # setup optimistic_locking
      {:ok, _} = RedisClient.conn_pipeline([~w(watch key)], conn_a)

      assert {:ok, [_, _, ["OK"]]} =
               RedisClient.conn_pipeline([~w(multi), ~w(set key other_value), ~w(exec)], conn_a)

      {:ok, "other_value"} = RedisClient.command(~w(get key))
    end
  end

  test "a new worker is added to the pool if it dies somehow" do
    assert %{available_workers: 10} = ConnectionPool.status()

    fn ->
      _conn = ConnectionPool.checkout()
      assert %{available_workers: 9} = ConnectionPool.status()
      # this process forgets to return the worker to the pool, which is bad
      # it dies with the process
    end
    |> Task.async()
    |> Task.await()

    # it may take a while for the pool to create a new worker
    Process.sleep(50)

    assert %{available_workers: 10} = ConnectionPool.status()
  end
end
