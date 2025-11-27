defmodule Charon.TokenFactory.Jwt.OtkCache do
  @moduledoc """
  Cache for Poly1305 one-time keys (OTKs).

  This module provides an ETS-based cache for Poly1305 message authentication code (MAC) keys.
  OTKs are used once to sign a message, and subsequently used many times to verify that message.
  Caching these keys improves performance by avoiding redundant key derivation operations.

  The cache is backed by a local ETS table with automatic expiration. A GenServer handles
  initialization, cleanup, and periodic pruning of expired entries.

  ## Usage

  Add this cache to your supervision tree:

      children = [
        Charon.TokenFactory.Jwt.OtkCache
      ]

  Or start it manually with custom options:

      Charon.TokenFactory.Jwt.OtkCache.start_link(
        name: MyOtkCache,
        table: :my_otk_table,
        prune_interval: :timer.minutes(30)
      )

  ## Examples

      # Store an OTK with expiration timestamp
      otk = :crypto.strong_rand_bytes(32)
      exp = System.system_time(:second) + 3600
      OtkCache.put("key_id", otk, exp)

      # Retrieve the OTK
      OtkCache.get("key_id")
      #=> <<...binary...>>

      # Manually trigger pruning of expired entries
      OtkCache.prune_now()
  """
  require Logger
  use GenServer
  import Charon.Internal

  @type table :: :ets.table()
  @type key :: any()
  @type value :: binary()
  @type exp :: integer()

  @doc """
  Start the OTK cache GenServer.

  ## Options

    - `:name` - The name to register the GenServer as (default: `#{inspect(__MODULE__)}`)
    - `:table` - The name for the ETS table (same as `:name` by default)
    - `:table_opts` - ETS table options (default: `[:set, :public, :named_table]`)
    - `:prune_interval` - Interval in milliseconds between automatic pruning (default: 1 hour)

  ## Examples

      {:ok, pid} = OtkCache.start_link()
      {:ok, pid} = OtkCache.start_link(name: MyCache, prune_interval: :timer.minutes(30))
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = opts[:name] || __MODULE__
    table = opts[:table] || name
    table_opts = opts[:table_opts] || [:set, :public, :named_table]
    prune_interval = opts[:prune_interval] || :timer.hours(1)

    GenServer.start_link(
      __MODULE__,
      %{table: table, prune_interval: prune_interval, table_opts: table_opts},
      name: name
    )
  end

  @doc """
  Store a value in the cache with an expiration timestamp.

  ## Parameters

    - `table` - The ETS table to use (default: `#{inspect(__MODULE__)}`)
    - `key` - The cache key
    - `value` - The OTK binary to cache
    - `exp` - Expiration timestamp in seconds since Unix epoch

  ## Returns

  `true` if the insert was successful.

  ## Examples

      exp = System.system_time(:second) + 3600
      OtkCache.put("key_id", <<1, 2, 3>>, exp)
      #=> true
  """
  @spec put(table(), key(), value(), exp()) :: true
  def put(table \\ __MODULE__, key, value, exp) do
    :ets.insert(table, {key, {exp, value}})
  end

  @doc """
  Retrieve a value from the cache.

  Returns the cached value if it exists, regardless of expiration.
  Expired entries are removed during periodic pruning.

  ## Parameters

    - `table` - The ETS table to use (default: `#{inspect(__MODULE__)}`)
    - `key` - The cache key to look up

  ## Returns

  The cached binary value, or `nil` if the key is not found.

  ## Examples

      OtkCache.get("key_id")
      #=> <<1, 2, 3>>

      OtkCache.get("nonexistent")
      #=> nil
  """
  @spec get(table(), key()) :: value() | nil
  def get(table \\ __MODULE__, key) do
    case :ets.lookup(table, key) do
      [{_key, {_exp, value}}] -> value
      _ -> nil
    end
  end

  @doc """
  Manually prune expired entries from the cache.

  This function removes all entries whose expiration timestamp is less than the current time.
  Pruning also happens automatically at the configured `prune_interval`.

  ## Parameters

    - `table` - The ETS table to prune (default: `#{inspect(__MODULE__)}`)

  ## Returns

  The number of entries that were deleted.

  ## Examples

      OtkCache.prune_now()
      #=> 5
  """
  @spec prune_now(table()) :: non_neg_integer()
  def prune_now(table \\ __MODULE__) do
    count = :ets.select_delete(table, [{{:_, {:"$1", :_}}, [{:<, :"$1", now()}], [true]}])
    Logger.debug("Pruned #{count} items")
    count
  end

  ##########
  # Server #
  ##########

  @impl true
  def init(state = %{table: table}) do
    ^table = :ets.new(state.table, state.table_opts)
    schedule_pruning(state)
    {:ok, state}
  end

  @impl true
  def handle_info(:prune, state) do
    prune_now(state.table)
    schedule_pruning(state)
    {:noreply, state}
  end

  defp schedule_pruning(state), do: Process.send_after(self(), :prune, state.prune_interval)
end
