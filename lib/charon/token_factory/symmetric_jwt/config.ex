defmodule Charon.TokenFactory.SymmetricJwt.Config do
  @moduledoc """
  Config module for `Charon.TokenFactory.SymmetricJwt`.
  """
  @enforce_keys []
  defstruct [
    :secret_override,
    algorithm: :sha256,
    json_module: Jason,
    gen_secret_salt: "Charon.TokenFactory.SymmetricJwt"
  ]

  @type t :: %__MODULE__{
          secret_override: (() -> binary()) | nil,
          algorithm: :sha256 | :sha384 | :sha512 | :poly1305,
          json_module: module(),
          gen_secret_salt: binary
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)

  @doc false
  def default(), do: from_enum([])
end
