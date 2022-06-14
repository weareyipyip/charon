defmodule Charon.AuthChallenge.PasswordChallenge do
  @moduledoc """
  Auth challenge implementing a standard user password using a Comeonin-compatible hashing module.

  ## Config

  Additional config is required for this module under `custom.charon_password_challenge`:

      Charon.Config.from_enum(
        ...,
        custom: %{
          charon_password_challenge: %{
            ...
          }
        }
      )

  The following configuration options are supported:
    - `:hashing_module` (required). A Comeonin-compatible password hashing module, for example `Argon2`.
    - `:password_hash_field` (optional, default `:password_hash`). The string field of the user struct that is used to store the password hash.
    - `:password_param` (optional, default "password"). The name of the param that contains the password (or new password).
    - `:current_password_param` (optional, default "current_password"). The name of the param that contains the current password (when setting up the challenge).
    - `:password_check` (optional, default `password_check/1`). Predicate that checks new passwords.
  """
  @challenge_name "password"
  use Charon.AuthChallenge
  alias Charon.Internal
  @custom_config_field :charon_password_challenge
  @defaults %{
    password_hash_field: :password_hash,
    password_param: "password",
    current_password_param: "current_password",
    password_check: &__MODULE__.password_check/1
  }
  @required [:hashing_module]

  @impl true
  def challenge_complete(conn, params, user, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      %{
        password_hash_field: field,
        password_param: pw_param,
        hashing_module: hashing_module
      } = process_config(config)

      with <<password::binary>> <- Map.get(params, pw_param, {:error, "#{pw_param} not found"}),
           {:ok, _} <- hashing_module.check_pass(user, password, hash_key: field) do
        {:ok, conn, nil}
      end
    end
  end

  @impl true
  def setup_complete(conn, params, user, config) do
    %{
      password_hash_field: field,
      password_param: pw_param,
      current_password_param: cpw_param,
      hashing_module: hashing_module,
      password_check: check
    } = process_config(config)

    with <<pw::binary>> <- Map.get(params, pw_param, {:error, "#{pw_param} not found"}),
         <<cpw::binary>> <- Map.get(params, cpw_param, {:error, "#{cpw_param} not found"}),
         {_, true} <- {:password_check, check.(pw)},
         {:ok, _} <- hashing_module.check_pass(user, cpw, hash_key: field),
         new_hash = hashing_module.hash_pwd_salt(pw),
         enabled = AuthChallenge.put_enabled(user, @challenge_name, config),
         params = %{config.enabled_auth_challenges_field => enabled, field => new_hash},
         {:ok, _} <- AuthChallenge.update_user(user, params, config) do
      {:ok, conn, nil}
    else
      {:password_check, _} -> {:error, "#{pw_param} does not meet requirements"}
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
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end
end
