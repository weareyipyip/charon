defmodule Charon.TokenPlugs.SigVerifyCache do
  @moduledoc since: "4.4.0"
  @moduledoc """
  Entrypoint for `Charon.TokenPlugs.SigVerifyCache.Behaviour` implementation.
  All functions delegate to the module configured as `:token_signature_cache_module` in
  `Charon.Config`.

  When `:token_signature_cache_module` is `nil`, caching is disabled entirely.
  """
  @behaviour __MODULE__.Behaviour

  @impl true
  def get(token_hash, config), do: config.token_signature_cache_module.get(token_hash, config)

  @impl true
  def put(token_hash, value, exp, config),
    do: config.token_signature_cache_module.put(token_hash, value, exp, config)
end
