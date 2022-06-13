defmodule Charon.AuthChallenge.BypassStageChallenge do
  @moduledoc """
  An auth challenge that is meant to implement "do not ask for MFA again on this machine" functionality.
  Setting up the challenge results in a "bypass token" that the client can store,
  and can be used to complete the challenge.
  """
  @challenge_name "bypass_stage"
  use Charon.AuthChallenge
  use Charon.Constants
  alias Charon.Internal
  @custom_config_field :charon_bypass_stage_challenge
  @defaults %{
    id_field: :id,
    param: "bypass_stage_token",
    bypass_stage_token_ttl: 6 * 30 * 24 * 60 * 60,
    cookie_name: "_bypass_stage_challenge_token_sig",
    cookie_opts: [
      http_only: true,
      same_site: "Strict",
      secure: true
    ]
  }
  @required []

  @impl true
  def challenge_complete(user, params, config) do
    # TODO this should be removed, the challenge is not enabled per-user but per-machine...
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      %{id_field: field, param: param} = process_config(config)
      user_id = Map.fetch!(user, field)
      token = Map.fetch!(params, param)

      with {:ok, payload} <- config.token_factory_module.verify(token, config),
           {_, %{"type" => "bypass_stage", "exp" => exp, "sub" => ^user_id}} <-
             {:payload, payload},
           {_, false} <- {:expired, Internal.now() > exp} do
        :ok
      else
        {:payload, _} -> {:error, "invalid token"}
        {:expired, _} -> {:error, "token expired"}
        error = {:error, <<_::binary>>} -> error
      end
    end
  end

  @impl true
  def setup_init(user, conn, config) do
    %{bypass_stage_token_ttl: ttl, cookie_name: cookie_name, cookie_opts: cookie_opts} =
      process_config(config)

    token = generate_token(user, config)

    case Internal.get_private(conn, @token_signature_transport) do
      :bearer ->
        {:ok, %{token: token}, conn}

      :cookie ->
        {token, signature, cookie_opts} = Internal.split_signature(token, ttl, cookie_opts)
        conn = Plug.Conn.put_resp_cookie(conn, cookie_name, signature, cookie_opts)
        {:ok, %{token: token}, conn}
    end
  end

  @impl true
  def setup_complete(user, _params, config) do
    enabled = AuthChallenge.put_enabled(user, @challenge_name, config)
    params = %{config.enabled_auth_challenges_field => enabled}
    {:ok, _user} = AuthChallenge.update_user(user, params, config)
    :ok
  end

  @doc false
  def generate_token(user, config) do
    %{id_field: field, bypass_stage_token_ttl: ttl} = process_config(config)
    user_id = Map.fetch!(user, field)
    now = Internal.now()
    payload = %{"type" => "bypass_stage", "exp" => now + ttl, "sub" => user_id}
    {:ok, token} = config.token_factory_module.sign(payload, config)
    token
  end

  def get_token_signature_from_cookie(conn = %{params: params}, config) do
    %{cookie_name: cookie_name, param: param} = process_config(config)
    token = Map.get(params, param) || ""

    with %{^cookie_name => signature} <- conn.cookies,
         true <- String.ends_with?(token, ".") do
      %{conn | params: Map.put(params, param, token <> signature)}
    else
      _ -> conn
    end
  end

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end
end
