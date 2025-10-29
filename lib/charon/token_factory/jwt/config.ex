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

  # def compile_init!(config) do
  #   mod_conf = Jwt.get_mod_conf(config)
  #   mod_conf = struct!(__MODULE__, mod_conf) |> Map.from_struct()
  #   Charon.OptMod.put_mod_conf(config, Jwt, mod_conf)
  # end

  # def runtime_init!(config), do: compile_init!(config)
end
