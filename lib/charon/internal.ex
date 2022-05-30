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
end
