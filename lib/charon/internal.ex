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
  Determine if the token transport mechanism is `:cookie_only`, `:bearer` or `:cookie`.
  """
  def parse_token_transport(token_transport)
  def parse_token_transport(t) when t in ~w(bearer cookie_only cookie)a, do: t
  def parse_token_transport("bearer"), do: :bearer
  def parse_token_transport("cookie_only"), do: :cookie_only
  def parse_token_transport("cookie"), do: :cookie

  def url_encode(data), do: Base.url_encode64(data, @url_enc_opts)
  def url_decode(data), do: Base.url_decode64(data, @url_enc_opts)
  def url_decode!(data), do: Base.url_decode64!(data, @url_enc_opts)
end
