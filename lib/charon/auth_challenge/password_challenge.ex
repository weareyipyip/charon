defmodule Charon.AuthChallenge.PasswordChallenge do
  @moduledoc """
  Auth challenge implementing a standard user password using a Comeonin-compatible hashing module.
  This challenge cannot be disabled for individual users, every user MUST have a password.

  ## Config

  Additional config is required for this module under `optional.charon_password_challenge`:

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          charon_password_challenge: %{
            ...
          }
        }
      )

  The following configuration options are supported:
    - `:new_password_param` (optional, default "new_password"). The name of the param that contains the password (or new password).
    - `:password_check` (optional, default `password_check/1`). Predicate that checks new passwords.
  """
  @challenge_name "password"
  use Charon.AuthChallenge
  alias Charon.Internal
  @optional_config_field :charon_password_challenge
  @defaults %{
    new_password_param: "new_password",
    password_check: &__MODULE__.password_check/1
  }
  @required []

  @impl true
  def challenge_complete(conn, params, user, config) do
    %{
      password_hash_field: field,
      password_hashing_module: hashing_module,
      current_password_param: pw_param
    } = config

    with <<password::binary>> <- Map.get(params, pw_param, {:error, "#{pw_param} not found"}),
         {:ok, _} <- hashing_module.check_pass(user, password, hash_key: field) do
      {:ok, conn, nil}
    end
  end

  @impl true
  def setup_complete(conn, params, user, config) do
    %{
      new_password_param: pw_param,
      password_check: check
    } = process_config(config)

    with {:ok, conn, _} <- super(conn, params, user, config),
         <<pw::binary>> <- Map.get(params, pw_param, {:error, "#{pw_param} not found"}),
         {_, true} <- {:password_check, check.(pw)},
         new_hash = config.password_hashing_module.hash_pwd_salt(pw),
         enabled = AuthChallenge.put_enabled(user, @challenge_name, config),
         params = %{
           config.enabled_auth_challenges_field => enabled,
           config.password_hash_field => new_hash
         },
         {:ok, _} <- AuthChallenge.update_user(user, params, config) do
      {:ok, conn, nil}
    else
      {:password_check, _} -> {:error, "#{pw_param} does not meet requirements"}
      error -> error
    end
  end

  @doc """
  Returns true if the password has at least 8 characters.
  """
  @spec password_check(binary) :: boolean
  def password_check(password), do: String.length(password) >= 8

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_optional_config(config, @optional_config_field, @defaults, @required)
  end
end
