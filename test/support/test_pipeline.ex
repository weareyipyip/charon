defmodule Charon.TestPipeline do
  @moduledoc false
  use Plug.Builder
  import Charon.TokenPlugs

  @config Charon.TestConfig.get()

  plug(:get_token_from_auth_header)
  plug(:fetch_cookies)
  plug(:get_token_from_cookie, @config.refresh_cookie_name)
  plug(:verify_token_signature, @config)
  plug(:verify_token_nbf_claim)
  plug(:verify_token_exp_claim)
  plug(:verify_token_claim_equals, type: "refresh")
  plug(:load_session, @config)
  plug(:verify_token_fresh, 5)
  plug(:emit_telemetry)
  plug(:verify_no_auth_error, &__MODULE__.errors/2)
  plug(Charon.TokenPlugs.PutAssigns, claims: %{"sub" => :current_user_id, "sid" => :session_id})

  def errors(conn, _), do: halt(conn)
end
