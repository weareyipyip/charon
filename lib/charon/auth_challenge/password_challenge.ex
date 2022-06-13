defmodule Charon.AuthChallenge.PasswordChallenge do
  @moduledoc """
  Auth challenge implementing a standard user password using a Comeonin-compatible hashing module.
  """
  @challenge_name "password"
  use Charon.AuthChallenge
  alias Charon.Internal
  @custom_config_field :charon_password_challenge
  @defaults %{
    password_hash_field: :password_hash,
    password_param: "password",
    current_password_param: "current_password"
  }
  @required [:hashing_module]

  @impl true
  def challenge_complete(user, params, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      %{
        password_hash_field: field,
        password_param: password_param,
        hashing_module: hashing_module
      } = process_config(config)

      password = Map.fetch!(params, password_param)

      with {:ok, _} <- hashing_module.check_pass(user, password, hash_key: field) do
        :ok
      end
    end
  end

  @impl true
  def setup_complete(user, params, config) do
    # TODO: do we really want to update through the challenge?
    %{password_param: password_param, current_password_param: current_password_param} =
      process_config(config)

    %{^password_param => pw, ^current_password_param => current_pw} = params
    enabled = AuthChallenge.put_enabled(user, @challenge_name, config)

    params = %{
      password_param => pw,
      current_password_param => current_pw,
      config.enabled_auth_challenges_field => enabled
    }

    with {:ok, _user} <- AuthChallenge.update_user(user, params, config) do
      :ok
    end
  end

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end
end
