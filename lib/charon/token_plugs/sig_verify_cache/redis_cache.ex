if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.TokenPlugs.SigVerifyCache.RedisCache do
    @moduledoc since: "4.4.0"
    @moduledoc """
    Redis-based implementation of `Charon.TokenPlugs.SigVerifyCache.Behaviour`.

    Unlike `Charon.TokenPlugs.SigVerifyCache.EtsCache`, this cache is shared across all
    nodes that connect to the same Redis instance, making it suitable for multi-node
    deployments.

    Requires `Charon.SessionStore.RedisStore.ConnectionPool` to be running in your
    supervision tree (already the case when `Charon.SessionStore.RedisStore` is used).

    ## Usage

        # config
        config :my_app, :charon,
          token_signature_cache_module: Charon.TokenPlugs.SigVerifyCache.RedisCache,
          ...

        # supervision tree (if not already started via RedisStore)
        children = [
          Charon.SessionStore.RedisStore.ConnectionPool
        ]
    """

    @behaviour Charon.TokenPlugs.SigVerifyCache.Behaviour

    alias Charon.SessionStore.RedisStore.RedisClient

    @impl true
    def get(token_hash, _config) do
      case RedisClient.command(["GET", key(token_hash)]) do
        {:ok, <<serialized::binary>>} -> {:hit, :erlang.binary_to_term(serialized)}
        _ -> :miss
      end
    end

    @impl true
    def put(token_hash, value, exp, _config) do
      RedisClient.command(["SET", key(token_hash), :erlang.term_to_binary(value), "EXAT", exp])
      :ok
    end

    @compile {:inline, key: 1}
    defp key(token_hash), do: ["charon:tc:", Base.url_encode64(token_hash, padding: false)]
  end
end
