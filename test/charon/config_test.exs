defmodule Charon.ConfigTest do
  use ExUnit.Case, async: true
  alias Charon.Internal.ConfigTest
  import Charon.Config
  doctest Charon.Config

  @configurations %{
    Charon.Config => %{
      token_issuer: :required,
      access_cookie_name: "_access_token_signature",
      access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
      access_token_ttl: 15 * 60,
      optional_modules: %{},
      refresh_cookie_name: "_refresh_token_signature",
      refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
      refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
      session_store_module: Charon.SessionStore.RedisStore,
      session_ttl: 365 * 24 * 60 * 60,
      token_factory_module: Charon.TokenFactory.SymmetricJwt
    },
    Charon.TokenFactory.SymmetricJwt.Config => %{
      get_secret: :required,
      algorithm: :sha256,
      json_module: Jason
    },
    Charon.SessionStore.RedisStore.Config => %{
      redix_module: :required,
      key_prefix: "charon_"
    }
  }

  describe "Configs" do
    test "default optional values" do
      ConfigTest.test_optional(@configurations)
    end

    test "require required values" do
      ConfigTest.test_required(@configurations)
    end
  end

  describe "Charon.Config.from_enum/1" do
    test "calls optional module config init" do
      base_config = @configurations[Charon.Config]
      config = %{base_config | optional_modules: %{Charon.SessionStore.RedisStore => %{}}}

      assert_raise ArgumentError,
                   "the following keys must also be given when building struct Charon.SessionStore.RedisStore.Config: [:redix_module]",
                   fn -> Charon.Config.from_enum(config) end
    end
  end
end
