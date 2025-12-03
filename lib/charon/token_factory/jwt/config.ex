defmodule Charon.TokenFactory.Jwt.Config do
  @moduledoc """
  Config module for `Charon.TokenFactory.Jwt`.

  ## Changing the signing key at runtime

  Do not modify `signing_key` directly on the config.
  Use `from_enum/1` to create a new config when changing the signing key, it
  pre-calculates derived config for performance.
  """
  alias Charon.TokenFactory.Jwt

  @enforce_keys []
  defstruct get_keyset: &Jwt.default_keyset/1,
            signing_key: "default",
            gen_poly1305_nonce: :random

  @type t :: %{
          get_keyset: (Charon.Config.t() -> Jwt.keyset()),
          signing_key: binary() | {binary(), binary()},
          gen_poly1305_nonce: :random | (-> <<_::96>>)
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum) do
    mod_conf = struct!(__MODULE__, enum) |> Map.from_struct()

    case mod_conf.signing_key do
      {_kid, _header_tail} ->
        mod_conf

      kid when is_binary(kid) ->
        header_tail = ~s("#{kid}"}) |> Charon.Internal.url_encode()
        %{mod_conf | signing_key: {kid, header_tail}}
    end
  end

  @doc """
  Get the config for this module from the parent `Charon.Config` struct.
  """
  @spec get_mod_config(Charon.Config.t()) :: t()
  def get_mod_config(_charon_config = %{optional_modules: %{Jwt => config}}), do: config
  def get_mod_config(_), do: from_enum([])
end
