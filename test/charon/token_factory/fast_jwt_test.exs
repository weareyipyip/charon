defmodule Charon.TokenFactory.FastJwtTest do
  use ExUnit.Case, async: true
  import Charon.Internal
  import Charon.TestUtils
  alias Charon.TokenFactory.Jwt
  alias Charon.TestFastJwt
  alias Jwt.Config

  # @ed25519_keypair Jwt.gen_keypair(:eddsa_ed25519)

  describe "HS256" do
    setup do
      config = TestFastJwt.Sha256.config()
      mod_conf = config |> Config.get_mod_config()
      %{"a" => {:hmac_sha256, key}} = mod_conf.get_keyset.(config)
      jwk = %{"k" => url_encode(key), "kty" => "oct"}
      [jwk: jwk, config: config]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = TestFastJwt.Sha256.sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.jwk, charon_token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = TestFastJwt.Sha256.sign(%{}, seeds.config)
      assert {:ok, _} = TestFastJwt.Sha256.verify(charon_token, seeds.config)
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "HS256", "kid" => "a"}
      {_, jose_token} = JOSE.JWT.sign(seeds.jwk, jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = TestFastJwt.Sha256.verify(jose_token, seeds.config)
    end

    test "FastJwt token can be verified by Jwt.verify", seeds do
      {:ok, token} = TestFastJwt.Sha256.sign(%{"foo" => "bar"}, seeds.config)
      assert {:ok, %{"foo" => "bar"}} = Jwt.verify(token, seeds.config)
    end
  end

  describe "Ed25519" do
    setup do
      config = TestFastJwt.Ed25519.config()
      mod_conf = config |> Config.get_mod_config()
      %{"d" => keypair = {:eddsa_ed25519, _}} = mod_conf.get_keyset.(config)
      pub_jwk = Jwt.keypair_to_pub_jwk(keypair)
      {_, {_, privkey}} = keypair
      jwk = pub_jwk |> Map.put("d", url_encode(privkey))
      jws = %{"alg" => "EdDSA", "kid" => "d", "typ" => "JWT"}
      %{pub_jwk: pub_jwk, jwk: jwk, jws: jws, config: config}
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = TestFastJwt.Ed25519.sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.pub_jwk, charon_token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = TestFastJwt.Ed25519.sign(%{}, seeds.config)
      assert {:ok, _} = TestFastJwt.Ed25519.verify(charon_token, seeds.config)
    end

    test "JOSE token can be verified by Charon", seeds do
      {_, jose_token} = seeds.jwk |> JOSE.JWT.sign(seeds.jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = TestFastJwt.Ed25519.verify(jose_token, seeds.config)
    end

    test "FastJwt token can be verified by Jwt.verify", seeds do
      {:ok, token} = TestFastJwt.Ed25519.sign(%{"foo" => "bar"}, seeds.config)
      assert {:ok, %{"foo" => "bar"}} = Jwt.verify(token, seeds.config)
    end
  end

  describe "Poly1305" do
    setup do
      config = TestFastJwt.Poly1305.config()
      mod_conf = config |> Config.get_mod_config()
      %{"c" => {:poly1305, key}} = mod_conf.get_keyset.(config)
      jwk = %{"k" => url_encode(key), "kty" => "oct"}
      [jwk: jwk, config: config]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, token} = TestFastJwt.Poly1305.sign(%{}, seeds.config)
      assert {true, _, _} = JOSE.JWT.verify(seeds.jwk, token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, charon_token} = TestFastJwt.Poly1305.sign(%{}, seeds.config)
      assert {:ok, %{}} == TestFastJwt.Poly1305.verify(charon_token, seeds.config)
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "Poly1305", "kid" => "c"}
      {_, jose_token} = JOSE.JWT.sign(seeds.jwk, jws, %{}) |> JOSE.JWS.compact()
      assert {:ok, _} = TestFastJwt.Poly1305.verify(jose_token, seeds.config)
    end

    test "FastJwt token can be verified by Jwt.verify", seeds do
      {:ok, token} = TestFastJwt.Poly1305.sign(%{"foo" => "bar"}, seeds.config)
      assert {:ok, %{"foo" => "bar"}} = Jwt.verify(token, seeds.config)
    end
  end

  describe "error handling" do
    setup do
      config = TestFastJwt.Sha256.config()
      [config: config]
    end

    test "gracefully handles malformed tokens", seeds do
      assert {:error, "malformed token"} = TestFastJwt.Sha256.verify("a", seeds.config)
    end

    test "handles invalid encoding", seeds do
      assert {:error, "encoding invalid"} = TestFastJwt.Sha256.verify("a.b.c", seeds.config)
    end

    test "handles invalid JSON in header", seeds do
      header = "notjson" |> url_encode()

      assert {:error, "json invalid"} =
               TestFastJwt.Sha256.verify(header <> ".YQ.YQ", seeds.config)
    end

    test "handles missing alg in header", seeds do
      header = %{"missing" => "alg"} |> Jason.encode!() |> url_encode()

      assert {:error, "malformed header"} =
               TestFastJwt.Sha256.verify(header <> ".YQ.YQ", seeds.config)
    end

    test "handles unsupported algorithm", seeds do
      header = %{"alg" => "boom"} |> Jason.encode!() |> url_encode()

      assert {:error, "key not found"} =
               TestFastJwt.Sha256.verify(header <> ".YQ.YQ", seeds.config)
    end

    test "handles invalid signature", seeds do
      header = Jwt.create_header(:hmac_sha256, "a", nil) |> IO.iodata_to_binary()

      assert {:error, "malformed token"} =
               TestFastJwt.Sha256.verify(header <> ".YQ.YQ", seeds.config)

      bad_sig = String.duplicate("a", 43)

      assert {:error, "signature invalid"} =
               TestFastJwt.Sha256.verify(header <> ".YQ." <> bad_sig, seeds.config)

      header =
        Jwt.create_header(:poly1305, "c", :crypto.strong_rand_bytes(12)) |> IO.iodata_to_binary()

      assert {:error, "signature invalid"} =
               TestFastJwt.Poly1305.verify(header <> ".YQ.YQ", seeds.config)
    end
  end

  describe "key cycling" do
    test "supports cycling to a new signing key while still verifying old tokens" do
      {:ok, token} = Jwt.sign(%{}, TestFastJwt.Ed25519.config())
      assert %{"alg" => "EdDSA", "kid" => "d"} = peek_header(token)

      assert {:ok, _} = TestFastJwt.Sha256.verify(token, TestFastJwt.Sha256.config())
      {:ok, new_token} = Jwt.sign(%{}, TestFastJwt.Sha256.config())
      assert new_token != token
    end
  end
end
