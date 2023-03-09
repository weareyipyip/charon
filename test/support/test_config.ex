defmodule Charon.TestConfig do
  def secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &__MODULE__.secret/0,
            session_store_module: Charon.SessionStore.LocalStore
          )

  def get(), do: @config
end
