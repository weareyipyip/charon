defmodule Charon.TokenFactory.JwtTest do
  use ExUnit.Case, async: true
  import Charon.Internal
  alias Charon.TokenFactory.Jwt
  alias Jwt.Config
  import Jwt

  @charon_config Charon.TestConfig.get()
  @ed25519_keypair Jwt.gen_keypair(:eddsa_ed25519)

  defp override_mod_config(config, overrides) do
    opt_mods = config.optional_modules
    mod_conf = config |> Config.get_mod_config() |> Map.merge(Map.new(overrides))
    opt_mods = Map.merge(opt_mods, %{Jwt => mod_conf})
    Map.put(config, :optional_modules, opt_mods)
  end

  describe "HS256" do
    setup do
      mod_conf = @charon_config |> Config.get_mod_config()
      base_key = mod_conf.get_keyset.(@charon_config)["default"] |> elem(1)
      encoded_key = Base.url_encode64(base_key, padding: false)
      jwk = %{"k" => encoded_key, "kty" => "oct"}
      [jwk: jwk]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = sign(%{}, @charon_config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.jwk, charon_token)
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "HS256", "kid" => "default"}
      {_, jose_token} = JOSE.JWT.sign(seeds.jwk, jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, @charon_config)
    end

    test "Charon and JOSE generate the same token", seeds do
      {:ok, charon_token} = sign(%{}, @charon_config)
      jws = %{"alg" => "HS256", "kid" => "default"}
      {_, jose_token} = JOSE.JWT.sign(seeds.jwk, jws, %{}) |> JOSE.JWS.compact()
      assert jose_token == charon_token
    end
  end

  describe "Ed25519" do
    setup do
      pub_jwk = Jwt.keypair_to_pub_jwk(@ed25519_keypair)
      {_, {_, privkey}} = @ed25519_keypair
      jwk = pub_jwk |> Map.put("d", url_encode(privkey))

      jws = %{"alg" => "EdDSA", "kid" => "ed25519_1", "typ" => "JWT"}

      config =
        override_mod_config(@charon_config,
          get_keyset: fn _ -> %{"ed25519_1" => @ed25519_keypair} end,
          signing_key: "ed25519_1"
        )

      %{keypair: @ed25519_keypair, pub_jwk: pub_jwk, jwk: jwk, jws: jws, config: config}
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.pub_jwk, charon_token)
    end

    test "JOSE token can be verified by Charon", seeds do
      {_, jose_token} = seeds.jwk |> JOSE.JWT.sign(seeds.jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, seeds.config)
    end

    test "Charon and JOSE generate the same token", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      {_, jose_token} = seeds.jwk |> JOSE.JWT.sign(seeds.jws, %{}) |> JOSE.JWS.compact()
      assert jose_token == charon_token
    end
  end

  doctest Jwt
end
