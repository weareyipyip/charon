defmodule Charon.TokenPlugs.SigVerifyCache.EtsCache do
  @moduledoc since: "4.4.0"
  @moduledoc """
  ETS-based implementation of `Charon.TokenPlugs.SigVerifyCache.Behaviour`.

  When used together with `Charon.TokenPlugs.verify_token_signature/2`,
  this cache stores the full verification result (success or failure) keyed by a SHA-256
  hash of the token. Subsequent requests with the same token skip the cryptographic
  signature verification entirely. This is especially beneficial for EdDSA tokens,
  where signature verification is expensive.

  Claim verification plugs such as `:verify_token_exp_claim` and `:verify_token_fresh`
  are **not** covered by the caching mechanism and still run on every request.

  ## Usage

  Add this cache to your supervision tree before using `verify_token_signature/2`:

      children = [
        Charon.TokenPlugs.SigVerifyCache.EtsCache
      ]

  ## Options

    - `:cleanup_interval` - interval in milliseconds between expired-entry cleanup passes
      (default: `60_000`)

  """

  @behaviour Charon.TokenPlugs.SigVerifyCache.Behaviour

  use GenServer

  @table __MODULE__
  @default_cleanup_interval 60_000

  @doc false
  def start_link(opts \\ []) do
    cleanup_interval = Keyword.get(opts, :cleanup_interval, @default_cleanup_interval)
    GenServer.start_link(__MODULE__, %{cleanup_interval: cleanup_interval}, name: __MODULE__)
  end

  @doc """
  Look up a cached verification result by the token's SHA-256 hash binary.

  Returns `{:hit, value}` if a non-expired entry is found, or `:miss` otherwise.
  """
  @impl true
  @spec get(binary(), Charon.Config.t()) :: {:hit, any()} | :miss
  def get(token_hash, _config) do
    now = System.os_time(:second)

    case :ets.lookup(@table, token_hash) do
      [{^token_hash, payload, exp}] when exp > now -> {:hit, payload}
      _ -> :miss
    end
  end

  @doc """
  Store a verification result in the cache, keyed by the token's SHA-256 hash binary.

  `exp` is the Unix timestamp (in seconds) at which the cache entry should be
  considered stale.
  """
  @impl true
  @spec put(binary(), any(), integer(), Charon.Config.t()) :: :ok
  def put(token_hash, payload, exp, _config) do
    :ets.insert(@table, {token_hash, payload, exp})
    :ok
  end

  ## GenServer callbacks

  @impl true
  def init(%{cleanup_interval: cleanup_interval}) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    schedule_cleanup(cleanup_interval)
    {:ok, %{cleanup_interval: cleanup_interval}}
  end

  @impl true
  def handle_info(:cleanup, state = %{cleanup_interval: cleanup_interval}) do
    now = System.os_time(:second)
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
    schedule_cleanup(cleanup_interval)
    {:noreply, state}
  end

  defp schedule_cleanup(interval), do: Process.send_after(self(), :cleanup, interval)
end
