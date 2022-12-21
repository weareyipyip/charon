defmodule Charon.TokenFactory.SymmetricJwt.Poly1305NonceFactory do
  @moduledoc """
  Poly1305 requires a non-repeating, but not necessarily unpredictable nonce.
  In a Poly1305 JWT, this nonce has a size of 96 bits,
  which is too small to safely generate random nonces.
  It is recommended to use a counter (https://datatracker.ietf.org/doc/html/rfc8439#section-2.6).
  To prevent us from having to store a global counter,
  we generate the first part of the nonce randomly when starting the agent,
  and the rest is a counter that is increased every time a nonce is requested.
  The random part is effectively cycled at application start.

  By default, the first 7 bytes are randomly generated, leaving the remaining 5 bytes for the counter.
  This gives 2^56 possibilities for the random part, and a max counter size of 2^40.
  """
  use Agent

  def start_link(opts \\ []) do
    name = opts[:name] || __MODULE__
    nonce_size = opts[:nonce_size] || 12
    random_size = opts[:random_size] || 7
    Agent.start_link(__MODULE__, :init_state, [nonce_size, random_size], name: name)
  end

  def get_nonce(name \\ __MODULE__),
    do: Agent.get_and_update(name, __MODULE__, :get_and_update, [])

  ###########
  # Private #
  ###########

  @doc false
  def init_state(nonce_size, random_size) do
    random_prefix = :crypto.strong_rand_bytes(random_size)
    nonce_bitsize = nonce_size * 8
    counter_bitsize = nonce_bitsize - random_size * 8
    <<nonce::size(nonce_bitsize)>> = <<random_prefix::binary, 0::size(counter_bitsize)>>
    {nonce, nonce_bitsize}
  end

  @doc false
  def get_and_update({nonce, bitsize}), do: {<<nonce::size(bitsize)>>, {nonce + 1, bitsize}}
end
