defmodule Charon.ConfigTest do
  use ExUnit.Case, async: true
  alias Charon.SessionStore.RedisStore
  alias Charon.TokenFactory.Jwt
  alias Charon.Internal.ConfigTest
  import Charon.{Config, TestHelpers}
  doctest Charon.Config

  @configurations %{
    Charon.Config => %{
      token_issuer: :required,
      get_base_secret: :required,
      access_cookie_name: "_access_token_signature",
      access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
      access_token_ttl: 15 * 60,
      json_module: Jason,
      optional_modules: %{},
      refresh_cookie_name: "_refresh_token_signature",
      refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
      refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
      session_store_module: RedisStore,
      session_ttl: 365 * 24 * 60 * 60,
      token_factory_module: Jwt
    },
    Jwt.Config => %{
      get_keyset: &Jwt.default_keyset/1,
      signing_key: "default"
    },
    RedisStore.Config => %{
      redix_module: :required,
      key_prefix: "charon_",
      get_signing_key: &RedisStore.default_signing_key/1,
      allow_unsigned?: true
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
      config = override_opt_mod_conf(base_config, RedisStore, %{})

      assert_raise ArgumentError,
                   "the following keys must also be given when building struct Charon.SessionStore.RedisStore.Config: [:redix_module]",
                   fn -> Charon.Config.from_enum(config) end
    end
  end
end
