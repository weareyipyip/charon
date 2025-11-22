defmodule Charon.TokenFactory.Behaviour do
  @moduledoc """
  Behaviour for token-signing modules.

  Note that the token payload must be returned as a map with string keys on verification.
  When the payload is serialized as JSON, this happens automatically.
  However, when Erlang term format is used, this is not the case.
  Given that verification is the hotter code path,
  it probably makes sense to convert atom keys to string keys on token creation,
  rather than on verification.
  """
  alias Charon.Config

  @doc """
  Create a new token with the provided payload and a valid signature.
  """
  @callback sign(payload :: %{required(String.t()) => any()}, config :: Config.t()) ::
              {:ok, String.t()} | {:error, String.t()}

  @doc """
  Verify that the signature matches the token's header and payload, and decode the payload.

  Must return a map of string keys.
  """
  @callback verify(token :: String.t(), config :: Config.t()) ::
              {:ok, %{required(String.t()) => any()}} | {:error, String.t()}
end
