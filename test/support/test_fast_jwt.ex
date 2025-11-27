defmodule Charon.TestFastJwt do
  @moduledoc false
  @poly1305_key <<61, 95, 141, 243, 240, 127, 73, 153, 220, 173, 198, 206, 235, 176, 136, 241,
                  135, 160, 59, 154, 250, 52, 156, 36, 49, 44, 83, 199, 61, 103, 36, 24>>
  @ed25519_key {<<89, 196, 121, 98, 207, 119, 202, 129, 121, 201, 104, 251, 68, 82, 231, 25, 12,
                  59, 242, 72, 17, 98, 224, 172, 56, 38, 249, 1, 233, 220, 67, 67>>,
                <<33, 171, 1, 67, 222, 166, 136, 27, 213, 202, 162, 120, 214, 106, 95, 4, 87, 53,
                  185, 91, 30, 85, 159, 43, 181, 90, 124, 10, 58, 217, 98, 115>>}

  def get_base_secret(), do: "supersupersecret"

  def get_keyset(_) do
    %{
      "a" => {:hmac_sha256, "supersecret"},
      "c" => {:poly1305, @poly1305_key},
      "d" => {:eddsa_ed25519, @ed25519_key}
    }
  end
end

defmodule Charon.TestFastJwt.Sha256 do
  @moduledoc false
  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &Charon.TestFastJwt.get_base_secret/0,
            session_store_module: Charon.SessionStore.DummyStore,
            optional_modules: %{
              Charon.TokenFactory.Jwt => [
                signing_key: "a",
                get_keyset: &Charon.TestFastJwt.get_keyset/1
              ]
            }
          )

  use Charon.TokenFactory.FastJwt, config: @config, signing_alg: :hmac_sha256

  def config(), do: @config
end

defmodule Charon.TestFastJwt.Ed25519 do
  @moduledoc false
  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &Charon.TestFastJwt.get_base_secret/0,
            session_store_module: Charon.SessionStore.DummyStore,
            optional_modules: %{
              Charon.TokenFactory.Jwt => [
                signing_key: "d",
                get_keyset: &Charon.TestFastJwt.get_keyset/1
              ]
            }
          )

  use Charon.TokenFactory.FastJwt, config: @config, signing_alg: :eddsa_ed25519

  def config(), do: @config
end

defmodule Charon.TestFastJwt.Poly1305 do
  @moduledoc false
  alias Charon.Utils.PersistentTermCache

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &Charon.TestFastJwt.get_base_secret/0,
            session_store_module: Charon.SessionStore.DummyStore,
            optional_modules: %{
              Charon.TokenFactory.Jwt => [
                signing_key: "c",
                get_keyset: &Charon.TestFastJwt.get_keyset/1,
                gen_poly1305_nonce: &__MODULE__.counter_nonce/0
              ]
            }
          )

  use Charon.TokenFactory.FastJwt, config: @config, signing_alg: :poly1305

  def config(), do: @config

  def counter_nonce() do
    ref = PersistentTermCache.get_or_create(__MODULE__, fn -> :atomics.new(1, signed: false) end)
    <<:atomics.add_get(ref, 1, 1)::96>>
  end
end
