alias Charon.{Internal, SessionPlugs, TokenPlugs, Utils}
alias Charon.Models.{Session, Tokens}
alias Charon.TokenFactory.SymmetricJwt
alias Charon.SessionStore.RedisStore
alias Charon.Config, as: CharonConfig

charon_config = CharonConfig.from_enum(token_issuer: "local", get_base_secret: fn -> "very secure string" end)
