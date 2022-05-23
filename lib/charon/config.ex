defmodule Charon.Config do
  @moduledoc """
  Config struct.

  ```
  [
    :token_secret,
    token_algorithm: :sha256,
    token_module: Charon.Token.SymmetricJwt,
    custom: %{}
  ]
  ```
  """

  @enforce_keys [:token_secret]
  defstruct [
    :token_secret,
    token_algorithm: :sha256,
    token_module: Charon.Token.SymmetricJwt,
    custom: %{}
  ]

  @type t :: %__MODULE__{
          token_secret: String.t(),
          token_algorithm: :sha256 | :poly1305,
          token_module: module(),
          custom: map()
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.

  ## Examples / doctests

      iex> from_enum([])
      ** (ArgumentError) the following keys must also be given when building struct Charon.Config: [:session_ttl, :refresh_token_ttl, :session_store_module]

      iex> %Charon.Config{} = from_enum([session_ttl: 30 * 24 * 60 * 60, refresh_token_ttl: 24 * 60 * 60, session_store_module: MyModule])
  """
  @spec from_enum(Enum.t()) :: %__MODULE__{}
  def from_enum(enum) do
    struct!(__MODULE__, enum)
  end
end
