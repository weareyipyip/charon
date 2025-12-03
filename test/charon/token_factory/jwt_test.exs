defmodule Charon.TokenFactory.JwtTest do
  use ExUnit.Case, async: true
  import Charon.{Internal, TestHelpers}
  import Charon.TestUtils
  alias Charon.TokenFactory.Jwt
  alias Jwt.Config
  import Jwt

  @charon_config TestApp.Charon.get()
  @ed25519_keypair Jwt.gen_keypair(:eddsa_ed25519)
  @ed448_keypair Jwt.gen_keypair(:eddsa_ed448)

  describe "HS256" do
    setup do
      mod_conf = @charon_config |> Config.get_mod_config()
      %{"default" => {_, key}} = mod_conf.get_keyset.(@charon_config)
      encoded_key = url_encode(key)
      jwk = %{"k" => encoded_key, "kty" => "oct"}
      [jwk: jwk]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = sign(%{}, @charon_config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.jwk, charon_token)
    end

    test "Charon token can be verified by Charon" do
      {:ok, charon_token} = sign(%{}, @charon_config)
      assert {:ok, _} = verify(charon_token, @charon_config)
    end

    test "Created token will be verified by fast path" do
      mod_conf = Config.get_mod_config(@charon_config)
      {_kid, header_tail} = mod_conf.signing_key
      {:ok, charon_token} = sign(%{}, @charon_config)
      expected = url_encode(~s({"alg":"HS256","typ":"JWT","kid":)) <> header_tail
      assert [^expected, _, _] = String.split(charon_token, ".")
      assert {:ok, json} = url_decode(expected)
      assert {:ok, %{"kid" => "default"}} = Jason.decode(json)
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

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert {:ok, _} = verify(charon_token, seeds.config)
    end

    test "Created token will be verified by fast path", seeds do
      mod_conf = Config.get_mod_config(seeds.config)
      {_kid, header_tail} = mod_conf.signing_key
      {:ok, charon_token} = sign(%{}, seeds.config)
      expected = url_encode(~s({"alg":"EdDSA","typ":"JWT","kid":)) <> header_tail
      assert [^expected, _, _] = String.split(charon_token, ".")
      assert {:ok, json} = url_decode(expected)
      assert {:ok, %{"kid" => "ed25519_1"}} = Jason.decode(json)
    end

    test "JOSE token can be verified by Charon", seeds do
      {_, jose_token} = seeds.jwk |> JOSE.JWT.sign(seeds.jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, seeds.config)
    end
  end

  describe "Ed448" do
    setup do
      pub_jwk = Jwt.keypair_to_pub_jwk(@ed448_keypair)
      {_, {_, privkey}} = @ed448_keypair
      jwk = pub_jwk |> Map.put("d", url_encode(privkey))

      jws = %{"alg" => "EdDSA", "kid" => "ed448_1", "typ" => "JWT"}

      config =
        override_opt_mod_conf(@charon_config, Jwt,
          get_keyset: fn _ -> %{"ed448_1" => @ed448_keypair} end,
          signing_key: "ed448_1"
        )

      %{keypair: @ed448_keypair, pub_jwk: pub_jwk, jwk: jwk, jws: jws, config: config}
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.pub_jwk, charon_token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert {:ok, _} = verify(charon_token, seeds.config)
    end

    test "Created token will be verified by fast path", seeds do
      mod_conf = Config.get_mod_config(seeds.config)
      {_kid, header_tail} = mod_conf.signing_key
      {:ok, charon_token} = sign(%{}, seeds.config)
      expected = url_encode(~s({"alg":"EdDSA","typ":"JWT","kid":)) <> header_tail
      assert [^expected, _, _] = String.split(charon_token, ".")
      assert {:ok, json} = url_decode(expected)
      assert {:ok, %{"kid" => "ed448_1"}} = Jason.decode(json)
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

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert {:ok, _} = verify(charon_token, seeds.config)
    end

    test "Created token will be verified by fast path", seeds do
      mod_conf = Config.get_mod_config(seeds.config)
      {_kid, header_tail} = mod_conf.signing_key
      {:ok, charon_token} = sign(%{}, seeds.config)
      assert %{"nonce" => enc_nonce} = peek_header(charon_token)

      expected =
        url_encode(~s({"alg":"Poly1305","typ":"JWT","nonce":"#{enc_nonce}","kid":)) <> header_tail

      assert [^expected, _, _] = String.split(charon_token, ".")
      assert {:ok, json} = url_decode(expected)
      assert {:ok, %{"kid" => "k1"}} = Jason.decode(json)
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
      assert nonce == token |> peek_header() |> Map.get("nonce") |> url_decode!()
    end
  end

  describe "error handling" do
    test "gracefully handles malformed tokens" do
      assert {:error, "malformed token"} = verify("a", @charon_config)
    end

    test "handles invalid encoding" do
      assert {:error, "encoding invalid"} = verify("a.b.c", @charon_config)
    end

    test "handles invalid JSON in header" do
      header = "notjson" |> url_encode()
      assert {:error, "json invalid"} = verify(header <> ".YQ.YQ", @charon_config)
    end

    test "handles missing alg in header" do
      header = %{"missing" => "alg"} |> Jason.encode!() |> url_encode()
      assert {:error, "malformed header"} = verify(header <> ".YQ.YQ", @charon_config)
    end

    test "handles unsupported algorithm" do
      header = %{"alg" => "boom"} |> Jason.encode!() |> url_encode()
      assert {:error, "key not found"} = verify(header <> ".YQ.YQ", @charon_config)
    end

    test "handles invalid signature" do
      header = %{"alg" => "HS256", "kid" => "default"} |> Jason.encode!() |> url_encode()
      assert {:error, "signature invalid"} = verify(header <> ".YQ.YQ", @charon_config)
    end
  end

  describe "key cycling" do
    test "supports cycling to a new signing key while still verifying old tokens" do
      {:ok, token} = sign(%{}, @charon_config)
      keyset = Jwt.default_keyset(@charon_config)
      keyset = Map.put(keyset, "ed25519_1", Jwt.gen_keypair(:eddsa_ed25519))

      config =
        override_opt_mod_conf(@charon_config, Jwt,
          get_keyset: fn _ -> keyset end,
          signing_key: "ed25519_1"
        )

      assert {:ok, _} = verify(token, config)
      {:ok, new_token} = sign(%{}, config)
      assert new_token != token
    end
  end

  describe "legacy tokens without kid claim" do
    test "can verify old/external/legacy token without kid claim using kid_not_set.<alg> key" do
      [header, pl] =
        [%{"alg" => "HS256"}, %{}]
        |> Enum.map(&Jason.encode!/1)
        |> Enum.map(&url_encode/1)

      base = "#{header}.#{pl}"
      key = :crypto.strong_rand_bytes(32)
      signature = :crypto.mac(:hmac, :sha256, key, base) |> url_encode()
      token = "#{base}.#{signature}"

      assert {:error, "key not found"} = verify(token, @charon_config)

      keyset = %{"kid_not_set.HS256" => {:hmac_sha256, key}}

      config =
        override_opt_mod_conf(
          @charon_config,
          Jwt,
          Jwt.Config.from_enum(get_keyset: fn _ -> keyset end)
        )

      assert {:ok, _} = verify(token, config)
    end
  end

  describe "fast path verification" do
    test "token with different kid falls back to full verify" do
      # Create token with one key
      {:ok, token} = sign(%{"data" => "test"}, @charon_config)

      # Change signing_key config but keep same keyset
      mod_conf = @charon_config |> Config.get_mod_config()
      keyset = mod_conf.get_keyset.(@charon_config)

      # Add a new key and change the signing key, but keep old key in keyset
      config =
        override_opt_mod_conf(@charon_config, Jwt,
          get_keyset: fn _ ->
            Map.put(keyset, "other_key", {:hmac_sha256, :crypto.strong_rand_bytes(32)})
          end,
          signing_key: "other_key"
        )

      # Old token should not match fast path pattern (different __header_tail)
      # but should still verify via full_verify
      assert {:ok, %{"data" => "test"}} = verify(token, config)
    end

    test "token with different algorithm falls back to full verify" do
      mod_conf = @charon_config |> Config.get_mod_config()
      %{"default" => {_, key}} = mod_conf.get_keyset.(@charon_config)

      # Create SHA256 token
      {:ok, sha256_token} = sign(%{"data" => "test"}, @charon_config)

      # Configure for SHA512 but include SHA256 key in keyset
      config =
        override_opt_mod_conf(@charon_config, Jwt,
          get_keyset: fn _ ->
            %{
              "default" => {:hmac_sha256, key},
              "sha512_key" => {:hmac_sha512, key}
            }
          end,
          signing_key: "sha512_key"
        )

      # SHA256 token should not match SHA512 fast path but should verify
      assert {:ok, %{"data" => "test"}} = verify(sha256_token, config)
    end
  end

  doctest Jwt
end
