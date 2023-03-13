alias Charon.{Internal, SessionPlugs, TokenPlugs, Utils, SessionStore, TokenFactory, Models}
alias Charon.Config, as: CharonConfig
alias Models.{Session, Tokens}
alias TokenFactory.Jwt
alias SessionStore.{RedisStore, LocalStore, DummyStore}
alias Internal.{Crypto}

RedisStore.ConnectionPool.start_link
charon_config = CharonConfig.from_enum(token_issuer: "local", get_base_secret: fn -> "very secure string" end)
