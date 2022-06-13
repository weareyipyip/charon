defmodule Charon.Utils do
  @moduledoc """
  Utility functions, mainly getters and setters for module internals.
  """
  use Charon.Constants
  alias Plug.Conn
  alias Charon.Models.{Session, Tokens}
  alias Charon.Internal

  @doc """
  Get current session, if present.
  """
  @spec get_session(Conn.t()) :: Session.t() | nil
  def get_session(conn), do: Internal.get_private(conn, @session)

  @doc """
  Get tokens, if present.
  """
  @spec get_tokens(Conn.t()) :: Tokens.t() | nil
  def get_tokens(conn), do: Internal.get_private(conn, @tokens)

  @doc """
  Get auth errors, if present.
  """
  @spec get_auth_error(Conn.t()) :: binary() | nil
  def get_auth_error(conn), do: Internal.get_private(conn, @auth_error)

  @doc """
  Get token signature transport mechanism, if present.
  """
  @spec get_token_signature_transport(Conn.t()) :: atom() | nil
  def get_token_signature_transport(conn),
    do: Internal.get_private(conn, @token_signature_transport)

  @doc """
  Set token signature transport mechanism. Must be one of
  `"bearer"`, `"cookie"`, `:bearer` or `:cookie`.

  ## Examples / doctests

      iex> :bearer = %Conn{} |> set_token_signature_transport("bearer") |> get_token_signature_transport()
      iex> :bearer = %Conn{} |> set_token_signature_transport(:bearer) |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport("cookie") |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport(:cookie) |> get_token_signature_transport()

      iex> set_token_signature_transport(%Conn{}, "anything else")
      ** (FunctionClauseError) no function clause matching in Charon.Internal.parse_sig_transport/1
  """
  @spec set_token_signature_transport(Conn.t(), binary() | :bearer | :cookie) :: Conn.t()
  def set_token_signature_transport(conn, token_signature_transport) do
    transport = Internal.parse_sig_transport(token_signature_transport)
    Conn.put_private(conn, @token_signature_transport, transport)
  end

  @doc """
  Set user id for session creation
  """
  @spec set_user_id(Conn.t(), any) :: Conn.t()
  def set_user_id(conn, user_id), do: Conn.put_private(conn, @user_id, user_id)
end
