import Config

config :logger, level: :info

config :charon, MyApp.Charon,
  base_secret: "compile",
  token_issuer: "my_app.com",
  session_store_module: Charon.SessionStore.RedisStore,
  optional_modules:
    %{
      # Charon.SessionStore.RedisStore => [],
      # Charon.SessionStore.RedisStore => [],
      # Charon.RedisClient => []
      # Charon.ConnectionPool => %{
      #   worker: Redix,
      #   worker_args: []
      # }
    }

import_config("#{config_env()}.exs")
