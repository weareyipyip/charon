defmodule Charon.Utils do
  @moduledoc """
  Utility functions, mainly getters and setters for module internals.
  """
  use Charon.Constants
  alias Plug.Conn
  alias Charon.Models.{Session, Tokens}

  @doc """
  Get current session, if present.
  """
  @spec get_session(Conn.t()) :: Session.t() | nil
  def get_session(conn), do: Map.get(conn.private, @private_session_key)

  @doc """
  Get tokens, if present.
  """
  @spec get_tokens(Conn.t()) :: Tokens.t() | nil
  def get_tokens(conn), do: Map.get(conn.private, @private_tokens_key)

  @doc """
  Get access token payload, if present.
  """
  @spec get_access_token_payload(Conn.t()) :: map() | nil
  def get_access_token_payload(conn), do: Map.get(conn.private, @private_access_token_payload_key)

  @doc """
  Get refresh token payload, if present.
  """
  @spec get_refresh_token_payload(Conn.t()) :: map() | nil
  def get_refresh_token_payload(conn),
    do: Map.get(conn.private, @private_refresh_token_payload_key)

  @doc """
  Get auth error, if present.
  """
  @spec get_auth_errors(Conn.t()) :: binary() | nil
  def get_auth_errors(conn), do: Map.get(conn.private, @private_auth_error_key)

  @doc """
  Get token signature transport mechanism, if present.
  """
  @spec get_token_signature_transport(Conn.t()) :: atom() | nil
  def get_token_signature_transport(conn),
    do: Map.get(conn.private, @private_token_signature_transport_key)

  @doc """
  Get user id, if present.
  """
  @spec get_user_id(Conn.t()) :: any()
  def get_user_id(conn), do: Map.get(conn.private, @private_user_id_key)

  @doc """
  Get session id, if present.
  """
  @spec get_session_id(Conn.t()) :: any()
  def get_session_id(conn), do: Map.get(conn.private, @private_session_id_key)

  @doc """
  Set token signature transport mechanism. Must be one of
  `"bearer"`, `"cookie"`, `:bearer` or `:cookie`.

  ## Examples / doctests

      iex> :bearer = %Conn{} |> set_token_signature_transport("bearer") |> get_token_signature_transport()
      iex> :bearer = %Conn{} |> set_token_signature_transport(:bearer) |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport("cookie") |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport(:cookie) |> get_token_signature_transport()

      iex> set_token_signature_transport(%Conn{}, "anything else")
      ** (FunctionClauseError) no function clause matching in Charon.Utils.set_token_signature_transport/2
  """
  @spec set_token_signature_transport(Conn.t(), binary() | :bearer | :cookie) :: Conn.t()
  def set_token_signature_transport(conn, token_signature_transport)
  def set_token_signature_transport(conn, "bearer"), do: set_tst(conn, :bearer)
  def set_token_signature_transport(conn, "cookie"), do: set_tst(conn, :cookie)
  def set_token_signature_transport(conn, :bearer), do: set_tst(conn, :bearer)
  def set_token_signature_transport(conn, :cookie), do: set_tst(conn, :cookie)

  @doc """
  Set user id for session creation
  """
  @spec set_user_id(Conn.t(), any) :: Conn.t()
  def set_user_id(conn, user_id), do: Conn.put_private(conn, @private_user_id_key, user_id)

  ###########
  # Private #
  ###########

  defp set_tst(conn, tst), do: Conn.put_private(conn, @private_token_signature_transport_key, tst)
end
