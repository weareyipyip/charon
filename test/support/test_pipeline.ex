defmodule Charon.TestPipeline do
  use Plug.Builder
  alias Charon.TestRedix
  import Charon.TokenPlugs

  def get_secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            optional_modules: %{
              charon_symmetric_jwt: %{get_secret: &__MODULE__.get_secret/0},
              charon_redis_store: %{redix_module: TestRedix}
            }
          )

  def config(), do: @config

  plug(:get_token_from_auth_header)
  plug(:get_token_sig_from_cookie, @config.refresh_cookie_name)
  plug(:verify_token_signature, @config)
  plug(:verify_token_nbf_claim)
  plug(:verify_token_exp_claim)
  plug(:verify_token_claim_equals, {"type", "refresh"})
  plug(:load_session, @config)
  plug(:verify_refresh_token_fresh)
  plug(:verify_no_auth_error, &__MODULE__.errors/2)
  plug(Charon.TokenPlugs.PutAssigns, user_id: :current_user_id)

  def errors(conn, _), do: halt(conn)
end
