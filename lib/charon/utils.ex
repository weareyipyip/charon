defmodule Charon.Utils do
  @moduledoc """
  Utility functions, mainly getters and setters for module internals.
  """
  use Charon.Internal.Constants
  alias Plug.Conn
  alias Charon.Models.{Session, Tokens}
  import Charon.Internal

  @doc """
  Get current session, if present.
  """
  @spec get_session(Conn.t()) :: Session.t() | nil
  def get_session(conn), do: get_private(conn, @session)

  @doc """
  Get tokens, if present.
  """
  @spec get_tokens(Conn.t()) :: Tokens.t() | nil
  def get_tokens(conn), do: get_private(conn, @tokens)

  @doc """
  Get auth errors, if present.
  """
  @spec get_auth_error(Conn.t()) :: binary() | nil
  def get_auth_error(conn), do: get_private(conn, @auth_error)

  @doc """
  Get the bearer token, if present.
  """
  @spec get_bearer_token(Conn.t()) :: map() | nil
  def get_bearer_token(conn), do: get_private(conn, @bearer_token)

  @doc """
  Get the payload of the bearer token, if present.
  """
  @spec get_bearer_token_payload(Conn.t()) :: map() | nil
  def get_bearer_token_payload(conn), do: get_private(conn, @bearer_token_payload)

  @doc """
  Get token transport mechanism, if present.
  """
  @doc since: "3.1.0"
  @spec get_token_transport(Conn.t()) :: atom() | nil
  def get_token_transport(conn), do: get_private(conn, @token_transport)

  @doc "Put an auth error on the conn"
  @spec set_auth_error(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_auth_error(conn, error), do: put_private(conn, @auth_error, error)

  @doc "Put a token payload on the conn"
  @spec set_token_payload(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_token_payload(conn, payload), do: put_private(conn, @bearer_token_payload, payload)

  @doc "Put a token on the conn"
  @spec set_token(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_token(conn, token), do: put_private(conn, @bearer_token, token)

  @doc "Put a session on the conn"
  @spec set_session(Plug.Conn.t(), any) :: Plug.Conn.t()
  def set_session(conn, session), do: put_private(conn, @session, session)
end
