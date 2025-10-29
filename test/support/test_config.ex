defmodule Charon.TestConfig do
  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            base_secret: "supersecret",
            session_store_module: Charon.SessionStore.LocalStore,
            refresh_cookie_opts: [path: "/api/refresh"]
          )

  def get(), do: @config
end
