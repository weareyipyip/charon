alias Charon.{Internal, SessionPlugs, TokenPlugs, Utils, SessionStore, TokenFactory, Models}
alias Charon.Config, as: CharonConfig
alias Models.{Session, Tokens}
alias TokenFactory.Jwt
alias SessionStore.{RedisStore, LocalStore, DummyStore}
alias Internal.{Crypto}

# RedisStore.start_link()
# charon_config = CharonConfig.from_enum(token_issuer: "local", base_secret: "very secure string")

{:ok, _} = Supervisor.start_link([MyApp.Charon], strategy: :one_for_one, name: MyApp.Supervisor)
Charon.RedisClient.attach_default_handler(debug_log?: true)
