defmodule Charon.TokenFactory.SymmetricJwtTest do
  use ExUnit.Case, async: true
  alias Charon.TokenFactory.SymmetricJwt
  import SymmetricJwt

  @payload %{"claim" => "value"}
  @config Charon.TestConfig.get()
  @mod_conf @config.optional_modules |> Map.get(SymmetricJwt, SymmetricJwt.Config.default())
  @base_key Charon.Internal.KeyGenerator.get_secret(
              Map.get(@mod_conf, :gen_secret_salt),
              32,
              @config
            )

  @encoded_key Base.url_encode64(@base_key, padding: false)
  @jwk %{"k" => @encoded_key, "kty" => "oct"}

  describe "HS256" do
    test "Charon token can be verified by JOSE" do
      {:ok, charon_token} = sign(@payload, @config)
      assert JOSE.JWT.verify(@jwk, charon_token)
    end

    test "JOSE token can be verified by Charon" do
      jws = %{"alg" => "HS256"}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert {:ok, _} = verify(jose_token, @config)
    end

    test "Charon and JOSE generate the same token" do
      {:ok, charon_token} = sign(@payload, @config)
      jws = %{"alg" => "HS256"}
      {_, jose_token} = JOSE.JWT.sign(@jwk, jws, @payload) |> JOSE.JWS.compact()
      assert jose_token == charon_token
    end
  end

  doctest SymmetricJwt
end
