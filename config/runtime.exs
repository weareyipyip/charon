import Config

config :charon, MyApp.Charon,
  base_secret: :crypto.strong_rand_bytes(64),
  optional_modules: %{}
