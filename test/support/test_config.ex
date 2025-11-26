defmodule Charon.TestConfig do
  @moduledoc false
  def secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &__MODULE__.secret/0,
            session_store_module: Charon.SessionStore.LocalStore,
            refresh_cookie_opts: [path: "/api/refresh"]
          )

  def get(), do: @config
end
