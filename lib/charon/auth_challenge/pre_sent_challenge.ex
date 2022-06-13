defmodule Charon.AuthChallenge.PreSentChallenge do
  @moduledoc """
  TOTP-challenge for which the answer has been sent to the user by SMS/email.
  Basically the same as `Charon.AuthChallenge.TotpChallenge` but with a longer default period (5 minutes).
  """
  @challenge_name "pre_sent"
  use Charon.AuthChallenge
  alias Charon.AuthChallenge.TotpChallenge
  alias Charon.Internal
  @custom_config_field :charon_pre_sent_challenge
  @defaults %{period: 5 * 60}
  @required [:send_challenge_callback]

  @impl true
  def challenge_init(user, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      %{send_challenge_callback: callback} = process_config(config)
      code = TotpChallenge.generate_code(user, override_config(config))
      callback.(user, code)
    end
  end

  @impl true
  def challenge_complete(user, params, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      config = override_config(config)
      TotpChallenge.challenge_complete(user, params, config)
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
  def generate_code(user, config) do
    config = override_config(config)
    TotpChallenge.generate_code(user, config)
  end

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end

  defp override_config(config = %{custom: custom}) do
    mod_config = config |> process_config() |> Map.merge(%{totp_label: "", totp_issuer: ""})
    %{config | custom: Map.put(custom, :charon_totp_challenge, mod_config)}
  end
end
