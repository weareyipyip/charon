defmodule Charon.TokenFactory.SymmetricJwt.Config do
  @moduledoc """
  Config module for `Charon.TokenFactory.SymmetricJwt`.
  """
  @enforce_keys [:get_secret]
  defstruct [:get_secret, algorithm: :sha256, json_module: Jason]

  @type t :: %__MODULE__{
          get_secret: (() -> binary()),
          algorithm: :sha256 | :sha384 | :sha512 | :poly1305,
          json_module: module()
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)
end
