defmodule Charon.TokenFactory.Jwt.Config do
  @moduledoc """
  Config module for `Charon.TokenFactory.Jwt`.
  """
  alias Charon.TokenFactory.Jwt

  @enforce_keys []
  defstruct get_keyset: &Jwt.default_keyset/1,
            signing_key: "default",
            gen_poly1305_nonce: :random

  @type t :: %__MODULE__{
          get_keyset: (Charon.Config.t() -> Jwt.keyset()),
          signing_key: binary,
          gen_poly1305_nonce: :random | (-> <<_::96>>)
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)

  @doc """
  Get the config for this module from the parent `Charon.Config` struct.
  """
  @spec get_mod_config(Charon.Config.t()) :: t()
  def get_mod_config(_charon_config = %{optional_modules: %{Jwt => config}}), do: config
  def get_mod_config(_), do: from_enum([])
end
