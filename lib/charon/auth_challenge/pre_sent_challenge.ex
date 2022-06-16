defmodule Charon.AuthChallenge.PreSentChallenge do
  @moduledoc """
  TOTP-challenge for which the answer has been sent to the user by SMS/email.
  Basically the same as `Charon.AuthChallenge.TotpChallenge` but with a longer default period (5 minutes).

  ## Config

  Additional config is required for this module under `custom.charon_pre_sent_challenge`:

      Charon.Config.from_enum(
        ...,
        custom: %{
          charon_pre_sent_challenge: %{
            ...
          }
        }
      )

  The following configuration options are supported:
    - `:send_challenge_callback` (required). A function/2 used to send a TOTP code to the user. The user and the code are passed in. Must return `:ok` or `{:error, message}`.
    - `:period` (optional, default 300). The duration in seconds in which a single OTP code is valid.
  """
  @challenge_name "pre_sent"
  use Charon.AuthChallenge
  alias Charon.AuthChallenge.TotpChallenge
  alias Charon.Internal
  @custom_config_field :charon_pre_sent_challenge
  @defaults %{period: 5 * 60}
  @required [:send_challenge_callback]

  @impl true
  def challenge_init(conn, params, user, config) do
    with {:ok, conn, _} <- super(conn, params, user, config),
         %{send_challenge_callback: callback} = process_config(config),
         code = TotpChallenge.generate_code(user, override_config(config)),
         :ok <- callback.(user, code) do
      {:ok, conn, nil}
    end
  end

  @impl true
  def challenge_complete(conn, params, user, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      config = override_config(config)
      TotpChallenge.challenge_complete(conn, params, user, config)
    end
  end

  @impl true
  def setup_complete(conn, params, user, config) do
    with {:ok, conn, _} <- super(conn, params, user, config),
         enabled = AuthChallenge.put_enabled(user, @challenge_name, config),
         params = %{config.enabled_auth_challenges_field => enabled},
         {:ok, _user} <- AuthChallenge.update_user(user, params, config) do
      {:ok, conn, nil}
    end
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
