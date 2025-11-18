defmodule Charon.TokenFactory.JwtTest do
  use ExUnit.Case, async: true
  import Charon.{Internal, TestHelpers}
  import Charon.TestUtils
  alias Charon.TokenFactory.Jwt
  alias Jwt.Config
  import Jwt

  @charon_config Charon.TestConfig.get()
  @ed25519_keypair Jwt.gen_keypair(:eddsa_ed25519)

  describe "HS256" do
    setup do
      mod_conf = @charon_config |> Config.get_mod_config()
      %{"default" => {_, key}} = mod_conf.get_keyset.(@charon_config)
      encoded_key = Base.url_encode64(key, padding: false)
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
  end

  describe "Ed25519" do
    setup do
      pub_jwk = Jwt.keypair_to_pub_jwk(@ed25519_keypair)
      {_, {_, privkey}} = @ed25519_keypair
      jwk = pub_jwk |> Map.put("d", url_encode(privkey))

      jws = %{"alg" => "EdDSA", "kid" => "ed25519_1", "typ" => "JWT"}

      config =
        override_opt_mod_conf(@charon_config, Jwt,
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
  end

  describe "Poly1305" do
    setup do
      mod_conf = @charon_config |> Config.get_mod_config()
      base_key = mod_conf.get_keyset.(@charon_config)["default"] |> elem(1)
      encoded_key = url_encode(base_key)
      jwk = %{"k" => encoded_key, "kty" => "oct"}

      config =
        override_opt_mod_conf(@charon_config, Jwt,
          get_keyset: fn _ -> %{"k1" => {:poly1305, base_key}} end,
          signing_key: "k1",
          gen_poly1305_nonce: :random
        )

      [config: config, jwk: jwk]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, token} = sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.jwk, token)
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "Poly1305", "kid" => "k1"}
      {_, jose_token} = JOSE.JWT.sign(seeds.jwk, jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, seeds.config)
    end

    test "token can use custom nonce generator", seeds do
      nonce = :crypto.strong_rand_bytes(12)
      config = override_opt_mod_conf(seeds.config, Jwt, gen_poly1305_nonce: fn -> nonce end)
      {:ok, token} = sign(%{}, config)

      assert nonce ==
               token |> peek_header() |> Map.get("nonce") |> Base.url_decode64!(padding: false)
    end
  end

  doctest Jwt
end
