defmodule Charon.Internal do
  @moduledoc false
  # module consists of shared functions internal to the package
  # it CAN be relied on by child packages, so be careful when changing things
  use __MODULE__.Constants
  require Logger

  @url_enc_opts padding: false

  @doc """
  Get a `now` unix timestamp
  """
  @spec now :: integer
  def now(), do: System.os_time(:second)

  @doc """
  Get the requests' `now` unix timestamp from conn or default to `now/0` result.
  """
  @spec now(Plug.Conn.t()) :: integer
  def now(_conn = %{private: %{@now => now}}), do: now
  def now(_conn), do: now()

  @doc """
  Get a value from the conn/resolution's private map
  """
  def get_private(_res = %{private: priv}, key), do: Map.get(priv, key)

  @doc """
  Merge a map into the conn/resolution's private map
  """
  def put_private(conn_or_res = %{private: priv}, map),
    do: %{conn_or_res | private: Map.merge(priv, map)}

  @doc """
  Put a key/value into the conn/resolution's private map
  """
  def put_private(conn_or_res = %{private: priv}, key, value),
    do: %{conn_or_res | private: Map.put(priv, key, value)}

  @doc """
  Generate a random URL-encoded string of `byte_size` bits.
  """
  @deprecated "Use `Charon.Utils.Crypto.random_url_encoded/1`"
  def random_url_encoded(byte_size), do: Charon.Internal.Crypto.random_url_encoded(byte_size)

  @doc """
  Determine if the token's signature transport mechanism is `:cookie` or `:bearer`.
  """
  def parse_sig_transport(token_signature_transport)
  def parse_sig_transport("bearer"), do: :bearer
  def parse_sig_transport("cookie"), do: :cookie
  def parse_sig_transport(:bearer), do: :bearer
  def parse_sig_transport(:cookie), do: :cookie

  @doc """
  Split the signature from a "header.payload.signature" token.
  """
  def split_signature(token, ttl, cookie_opts) do
    [header, payload, signature] = String.split(token, ".", parts: 3)
    token = [header, ?., payload, ?.] |> IO.iodata_to_binary()
    cookie_opts = Keyword.put(cookie_opts, :max_age, ttl)
    {token, signature, cookie_opts}
  end

  def url_encode(data), do: Base.url_encode64(data, @url_enc_opts)
  def url_decode(data), do: Base.url_decode64(data, @url_enc_opts)
  def url_decode!(data), do: Base.url_decode64!(data, @url_enc_opts)
end
