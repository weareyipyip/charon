defmodule Charon.TestHelpers do
  @moduledoc """
  Utility functions for writing tests.
  """
  use Charon.Internal.Constants
  import Charon.Internal

  @doc "Put an auth error on the conn"
  @spec set_auth_error(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_auth_error(conn, error), do: auth_error(conn, error)

  @doc "Put a token payload on the conn"
  @spec set_token_payload(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_token_payload(conn, payload), do: put_private(conn, @bearer_token_payload, payload)

  @doc "Put a token on the conn"
  @spec set_token(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_token(conn, payload), do: put_private(conn, @bearer_token, payload)

  @doc "Put a session on the conn"
  @spec set_session(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_session(conn, payload), do: put_private(conn, @session, payload)
end
