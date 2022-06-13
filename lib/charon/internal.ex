defmodule Charon.Internal do
  @moduledoc false
  # module consists of shared functions internal to the package
  use Charon.Constants
  require Logger
  alias Plug.Conn

  def auth_error(conn, error) do
    Conn.put_private(conn, @auth_error, error)
  end

  def now(), do: System.system_time(:second)

  def get_private(_conn = %{private: priv}, key), do: Map.get(priv, key)

  def put_private(conn = %{private: priv}, map) do
    %{conn | private: Map.merge(priv, map)}
  end

  # generate random IDs of a specified bit length, default 128
  # 2^128 == 16^32 so 128 bits of randomness is equal to a UUID (actually slightly more)
  def random_url_encoded(byte_size) do
    byte_size |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  def process_custom_config(config, custom_key, defaults, required) do
    custom = Map.fetch!(config.custom, custom_key)
    Enum.each(required, &Map.fetch!(custom, &1))
    Map.merge(defaults, custom)
  end

  def parse_sig_transport(token_signature_transport)
  def parse_sig_transport("bearer"), do: :bearer
  def parse_sig_transport("cookie"), do: :cookie
  def parse_sig_transport(:bearer), do: :bearer
  def parse_sig_transport(:cookie), do: :cookie

  def split_signature(token, ttl, cookie_opts) do
    [header, payload, signature] = String.split(token, ".", parts: 3)
    token = [header, ?., payload, ?.] |> IO.iodata_to_binary()
    cookie_opts = Keyword.put(cookie_opts, :max_age, ttl)
    {token, signature, cookie_opts}
  end
end
