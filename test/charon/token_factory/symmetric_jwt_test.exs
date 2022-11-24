defmodule Charon.TokenFactory.SymmetricJwtTest do
  use ExUnit.Case, async: true
  alias Charon.TokenFactory.SymmetricJwt
  import SymmetricJwt

  @base_key :crypto.strong_rand_bytes(32)
  @encoded_key Base.url_encode64(@base_key, padding: false)
  @payload %{"iss" => "joe", "exp" => 1_300_819_380, "http://example.com/is_root" => true}
  @jwk %{"k" => @encoded_key, "kty" => "oct"}

  describe "HS256" do
    setup do
      mod_conf = SymmetricJwt.Config.from_enum(get_secret: fn -> @base_key end)
      config = %{optional_modules: %{SymmetricJwt => mod_conf}}
      [config: config]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, charon_token} = sign(@payload, seeds.config)
      assert JOSE.JWT.verify(@jwk, charon_token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, token} = sign(@payload, seeds.config)
      assert {:ok, _} = verify(token, seeds.config)
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "HS256"}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, seeds.config)
    end

    test "Charon and JOSE generate the same token", seeds do
      {:ok, charon_token} = sign(@payload, seeds.config)
      jws = %{"alg" => "HS256"}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert jose_token == charon_token
    end
  end

  describe "Poly1305" do
    setup do
      mod_conf =
        SymmetricJwt.Config.from_enum(get_secret: fn -> @base_key end, algorithm: :poly1305)

      config = %{optional_modules: %{SymmetricJwt => mod_conf}}
      [config: config]
    end

    test "Charon token can be verified by JOSE", seeds do
      {:ok, token} = sign(@payload, seeds.config)
      assert JOSE.JWT.verify(@jwk, token)
    end

    test "Charon token can be verified by Charon", seeds do
      {:ok, token} = sign(@payload, seeds.config)
      assert {:ok, _} = verify(token, seeds.config)
    end

    test "Charon and JOSE generate the same token", seeds do
      {:ok, charon_token} = sign(@payload, seeds.config)

      [h, _p, _s] =
        charon_token |> String.split(".") |> Enum.map(&Base.url_decode64!(&1, padding: false))

      %{"nonce" => nonce} = Jason.decode!(h)

      jws = %{"alg" => "Poly1305", "nonce" => nonce}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert jose_token == charon_token
    end

    test "JOSE token can be verified by Charon", seeds do
      jws = %{"alg" => "Poly1305"}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, seeds.config)
    end
  end

  doctest SymmetricJwt
end
