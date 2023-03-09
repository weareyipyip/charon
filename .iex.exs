alias Charon.{Internal, SessionPlugs, TokenPlugs, Utils, SessionStore}
alias Charon.Models.{Session, Tokens}
alias Charon.TokenFactory.Jwt
alias Charon.SessionStore.RedisStore
alias Charon.Config, as: CharonConfig

charon_config = CharonConfig.from_enum(token_issuer: "local", get_base_secret: fn -> "very secure string" end)
