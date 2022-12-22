defmodule Charon.TokenFactory.SymmetricJwtTest do
  use ExUnit.Case, async: true
  alias Charon.TokenFactory.SymmetricJwt
  import SymmetricJwt

  @base_key :crypto.strong_rand_bytes(32)
  @payload %{"claim" => "value"}
  @mod_conf SymmetricJwt.Config.from_enum(get_secret: &__MODULE__.get_secret/0)
  @config %{optional_modules: %{SymmetricJwt => @mod_conf}}

  def get_secret(), do: @base_key

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
