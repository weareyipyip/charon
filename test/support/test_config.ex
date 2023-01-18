defmodule Charon.TestConfig do
  def secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &__MODULE__.secret/0,
            optional_modules: %{
              Charon.SessionStore.RedisStore => %{redix_module: Charon.TestRedix}
            }
          )

  def get(), do: @config
end
