defmodule Charon.Internal do
  @moduledoc false
  # module consists of shared functions internal to the package
  use __MODULE__.Constants
  require Logger
  alias Plug.Conn

  @doc """
  Put an auth error on the conn
  """
  def auth_error(conn, error), do: Conn.put_private(conn, @auth_error, error)

  @doc """
  Get a `now` unix timestamp
  """
  def now(), do: System.os_time(:second)

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
  def random_url_encoded(byte_size) do
    byte_size |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

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
end
