defmodule Charon.AuthFlowController do
  use Plug.Router
  alias Charon.{AuthFlow, AuthFlow.Stage, AuthChallenge, UserContext, TestRedix, Utils}

  alias AuthChallenge.{
    PasswordChallenge,
    TotpChallenge,
    BypassStageChallenge,
    RecoveryCodeChallenge,
    PreSentChallenge
  }

  import BypassStageChallenge, only: [get_token_signature_from_cookie: 2]

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            update_user_callback: &UserContext.update/2,
            custom: %{
              charon_symmetric_jwt: %{get_secret: &__MODULE__.get_secret/0},
              charon_redis_store: %{redix_module: TestRedix},
              charon_password_challenge: %{hashing_module: Bcrypt},
              charon_totp_challenge: %{totp_label: "MyApp", totp_issuer: "MyApp"},
              charon_pre_sent_challenge: %{
                send_challenge_callback: &__MODULE__.send_challenge_callback/2
              },
              charon_recovery_code_challenge: %{},
              charon_bypass_stage_challenge: %{}
            }
          )

  @flows AuthFlow.list_to_flow_set([
           %AuthFlow{
             name: "single",
             stages: [%Stage{challenges: Stage.list_to_challenge_set([PasswordChallenge])}]
           },
           %AuthFlow{
             name: "mfa",
             stages: [
               %Stage{challenges: Stage.list_to_challenge_set([PasswordChallenge])},
               %Stage{
                 challenges:
                   Stage.list_to_challenge_set([
                     TotpChallenge,
                     BypassStageChallenge,
                     RecoveryCodeChallenge,
                     PreSentChallenge
                   ])
               }
             ]
           }
         ])
  @challenge_map AuthFlow.to_challenge_map(@flows)

  plug(:match)
  plug(:get_token_signature_from_cookie, @config)
  plug(:dispatch)

  post "/init_flow" do
    %{"flow" => flow_name, "email" => email, "token_sig_transport" => sig_transport} = conn.params

    with {_, user = %{}} <- {:user, UserContext.get_by_email(email)},
         {:ok, token, stage} <- AuthFlow.init(user, @flows, flow_name, sig_transport, @config) do
      challenges = Map.keys(stage.challenges)
      json_resp(conn, 201, %{token: token, challenges: challenges})
    else
      {:flow, _} -> json_resp(conn, 400, %{error: "flow not recognized"})
      {:user, _} -> json_resp(conn, 404, %{error: "user not found"})
      {:error, msg} -> json_resp(conn, 500, %{error: msg})
    end
  end

  post "/init_challenge/:name" do
    %{"token" => token} = conn.params

    with {:ok, challenge, session} <- AuthFlow.process_token(token, @flows, name, @config),
         user = %{} <- UserContext.get_by_id(session.user_id),
         :ok <- challenge.challenge_init(user, @config) do
      send_resp(conn, 204, "")
    else
      nil -> json_resp(conn, 404, %{error: "user not found"})
      {:error, msg} -> json_resp(conn, 400, %{error: msg})
    end
  end

  post "/complete_challenge/:name" do
    %{"token" => token} = conn.params

    with {:ok, challenge, session} <- AuthFlow.process_token(token, @flows, name, @config),
         user = %{} <- UserContext.get_by_id(session.user_id) do
      result = challenge.challenge_complete(user, conn.params, @config)

      case AuthFlow.handle_challenge_result(result, @flows, session, conn, @config) do
        {:ok, :flow_complete, conn} ->
          tokens = conn |> Utils.get_tokens() |> Map.from_struct()
          json_resp(conn, 201, tokens)

        {:ok, :challenge_complete, next_stage} ->
          challenges = Map.keys(next_stage.challenges)
          json_resp(conn, 200, %{challenges: challenges})

        {:error, msg} ->
          json_resp(conn, 400, %{error: msg})
      end
    else
      nil -> json_resp(conn, 404, %{error: "user not found"})
      {:error, msg} -> json_resp(conn, 400, %{error: msg})
    end
  end

  ###########
  # Private #
  ###########

  def json_resp(conn, status, resp) do
    %{conn | status: status, resp_body: resp}
  end

  def send_challenge_callback(_user, _code), do: :ok

  def get_config(), do: @config
  def get_flows(), do: @flows
  def get_challenge_map(), do: @challenge_map
  def get_secret(), do: "supersecret"
end
