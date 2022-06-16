defmodule Charon.AuthChallenge.BypassStageChallenge do
  @moduledoc """
  An auth challenge that is meant to implement "do not ask for MFA again on this machine" functionality.
  Setting up the challenge results in a "bypass token" that the client can store,
  and can be used to complete the challenge.
  This challenge cannot be disabled for individual users.
  Clients should simply offer users an option to set it up or not, for the current device.

  ## Config

  Additional config is required for this module under `custom.charon_bypass_stage_challenge`:

      Charon.Config.from_enum(
        ...,
        custom: %{
          charon_bypass_stage_challenge: %{
            ...
          }
        }
      )

  The following configuration options are supported:
    - `:param` (optional, default: "bypass_stage_token"). The name of the param that contains the bypass token.
    - `:id_field` (optional, default: `:id`). The id field of the user struct that is used to store the user's unique ID.
    - `:bypass_stage_token_ttl` (optional, default 6 months). For how long the stage can be bypassed.
    - `:cookie_name` (optional, default "_bypass_stage_challenge_token_sig"). The name of the cookie that is optionally used to store the bypass stage token's signature for browser clients.
    - `:cookie_opts` (optional, default `[http_only: true, same_site: "Strict", secure: true]`). The options passed to `Plug.Conn.put_resp_cookie/4` when creating the cookie that is optionally used to store the bypass stage token's signature for browser clients.
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
    cookie_opts: [http_only: true, same_site: "Strict", secure: true]
  }
  @required []
  @token_type "charon_#{@challenge_name}"

  @impl true
  def challenge_complete(conn, params, user, config) do
    %{id_field: field, param: param} = process_config(config)
    user_id = Map.fetch!(user, field)

    with <<token::binary>> <- Map.get(params, param, {:error, "#{param} not found"}),
         token = get_token_signature_from_cookie(token, conn, config),
         {:ok, payload} <- config.token_factory_module.verify(token, config),
         {_, %{"type" => @token_type, "exp" => exp, "sub" => ^user_id}} <-
           {:payload, payload},
         {_, false} <- {:expired, Internal.now() > exp} do
      {:ok, conn, nil}
    else
      {:payload, _} -> {:error, "invalid token"}
      {:expired, _} -> {:error, "token expired"}
      error = {:error, <<_::binary>>} -> error
    end
  end

  @impl true
  def setup_complete(conn, params, user, config) do
    with {:ok, conn, _} <- super(conn, params, user, config) do
      %{bypass_stage_token_ttl: ttl, cookie_name: cookie_name, cookie_opts: cookie_opts} =
        process_config(config)

      token = generate_token(user, config)

      case Internal.get_private(conn, @token_signature_transport) do
        :cookie ->
          {token, signature, cookie_opts} = Internal.split_signature(token, ttl, cookie_opts)
          conn = Plug.Conn.put_resp_cookie(conn, cookie_name, signature, cookie_opts)
          {:ok, conn, %{token: token}}

        _ ->
          {:ok, conn, %{token: token}}
      end
    end
  end

  @doc false
  def generate_token(user, config) do
    %{id_field: field, bypass_stage_token_ttl: ttl} = process_config(config)
    user_id = Map.fetch!(user, field)
    now = Internal.now()
    payload = %{"type" => @token_type, "exp" => now + ttl, "sub" => user_id}
    {:ok, token} = config.token_factory_module.sign(payload, config)
    token
  end

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end

  defp get_token_signature_from_cookie(token, conn, config) do
    %{cookie_name: cookie_name} = process_config(config)
    conn = Plug.Conn.fetch_cookies(conn)

    with %{^cookie_name => signature} <- conn.cookies,
         true <- String.ends_with?(token, ".") do
      token <> signature
    else
      _ -> token
    end
  end
end
