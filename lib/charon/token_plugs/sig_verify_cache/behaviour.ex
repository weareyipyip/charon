defmodule Charon.TokenPlugs.SigVerifyCache.Behaviour do
  @moduledoc since: "4.4.0"
  @moduledoc """
  Behaviour for token signature cache backends used by
  `Charon.TokenPlugs.verify_token_signature/2`.

  Implementations must provide two functions:

    - `get/2` — look up a cached verification result by token hash
    - `put/4` — store a verification result with an expiry timestamp

  The default implementation is `Charon.TokenPlugs.SigVerifyCache.EtsCache`, an ETS-based
  local cache. For multi-node deployments you may supply a custom module that
  delegates to a shared store such as Redis.
  """
  alias Charon.Config

  @doc """
  Look up a cached verification result by the token's SHA-256 hash binary.

  Returns `{:hit, value}` if a live entry exists, or `:miss` otherwise.
  """
  @callback get(token_hash :: binary(), config :: Config.t()) :: {:hit, any()} | :miss

  @doc """
  Store a verification result keyed by the token's SHA-256 hash binary.

  `exp` is the Unix timestamp (in seconds) at which the entry should be
  considered stale.
  """
  @callback put(token_hash :: binary(), value :: any(), exp :: integer(), config :: Config.t()) ::
              :ok
end
