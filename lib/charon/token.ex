defmodule Charon.Token do
  @moduledoc """
  Behaviour for token-signing modules.
  """
  alias Charon.Config

  @doc """
  Create a new token with the provided payload and a valid signature.
  """
  @callback sign(payload :: map, config :: Config) :: {:ok, String.t()} | {:error, String.t()}

  @doc """
  Verify that the signature matches the token's header and payload, and decode the payload.
  """
  @callback verify(token :: String.t(), config :: Config) :: {:ok, map()} | {:error, String.t()}
end
