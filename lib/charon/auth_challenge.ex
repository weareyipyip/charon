defmodule Charon.AuthChallenge do
  @moduledoc """
  Behaviour for an authentication challenge module.
  """
  alias Charon.{Config, Internal}
  alias Plug.Conn

  defmacro __using__(_opts) do
    quote do
      alias Charon.AuthChallenge
      @behaviour AuthChallenge

      def name(), do: @challenge_name

      def challenge_init(conn, _params, user, config) do
        with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
          {:ok, conn, nil}
        end
      end

      def setup_init(conn, params, user, config) do
        with :ok <- AuthChallenge.check_current_password(user, params, config) do
          token = AuthChallenge.gen_setup_token(@challenge_name, config)
          {:ok, conn, %{config.auth_challenge_setup_token_param => token}}
        end
      end

      def setup_complete(conn, params, user, config) do
        with {:ok, _payload} <-
               AuthChallenge.validate_setup_token(@challenge_name, params, config) do
          {:ok, conn, nil}
        end
      end

      defoverridable AuthChallenge
    end
  end

  @typedoc """
  A module that implements this behaviour.
  """
  @type t :: module()

  @doc """
  Initiate the challenge.
  This callback can be used to issue the challenge, in response to the user picking it, for example by sending a code by email.
  This callback may optionally verify that the user has enabled the challenge.

  Returns:
  - `{:ok, maybe-updated-conn, maybe-response-for-client}`
  - `{:error, message}`
  - `{:error, map}` (update-user-callback-error)
  """
  @callback challenge_init(
              conn :: Conn.t(),
              params :: map(),
              user :: map() | struct(),
              config :: Config.t()
            ) ::
              {:ok, Conn.t(), nil | map()} | {:error, String.t()} | {:error, map()}

  @doc """
  Complete the challenge.
  This callback must validate the client's response to the challenge.
  Passing the challenge means passing the auth flow's stage.

  Returns:
  - `{:ok, maybe-updated-conn, maybe-response-for-client}`
  - `{:error, message}`
  - `{:error, map}` (update-user-callback-error)
  """
  @callback challenge_complete(
              conn :: Conn.t(),
              params :: map(),
              user :: map() | struct(),
              config :: Config.t()
            ) ::
              {:ok, Conn.t(), nil | map()} | {:error, String.t()} | {:error, map()}

  @doc """
  Initiate the challenge's setup.
  This callback should at least generate a setup token to complete the challenge setup.
  Additionally, it can be used to generate an initial challenge
  (for example to verify that the user has successfully set up an OTP app).

  Returns:
  - `{:ok, maybe-updated-conn, maybe-response-for-client}`
  - `{:error, message}`
  - `{:error, map}` (update-user-callback-error)
  """
  @callback setup_init(
              conn :: Conn.t(),
              params :: map(),
              user :: map() | struct(),
              config :: Config.t()
            ) ::
              {:ok, Conn.t(), nil | map()} | {:error, String.t()} | {:error, map()}

  @doc """
  Complete the challenge's setup.
  This callback should enable the challenge for the user, when applicable.

  Returns:
  - `{:ok, maybe-updated-conn, maybe-response-for-client}`
  - `{:error, message}`
  - `{:error, map}` (update-user-callback-error)
  """
  @callback setup_complete(
              conn :: Conn.t(),
              params :: map(),
              user :: map() | struct(),
              config :: Config.t()
            ) ::
              {:ok, Conn.t(), nil | map()} | {:error, String.t()} | {:error, map()}

  @doc """
  Returns the challenge's name. Should be unique.
  """
  @callback name() :: String.t()

  @doc """
  Generate a token that can be used to complete the setup of an auth challenge.
  """
  @spec gen_setup_token(String.t(), Config.t(), map) :: String.t()
  def gen_setup_token(challenge_name, config, extra_payload \\ %{}) do
    now = Internal.now()

    base_payload = %{
      "type" => "charon_setup_challenge",
      "exp" => now + 10 * 60,
      "challenge" => challenge_name
    }

    payload = Map.merge(base_payload, extra_payload)
    {:ok, token} = config.token_factory_module.sign(payload, config)
    token
  end

  @doc """
  Validate a token to complete the setup of an auth challenge.
  """
  @spec validate_setup_token(String.t(), map, Config.t()) :: {:error, String.t()} | {:ok, map}
  def validate_setup_token(challenge_name, params, config) do
    param = config.auth_challenge_setup_token_param

    with <<token::binary>> <- Map.get(params, param, {:error, "#{param} not found"}),
         {:ok, payload} <- config.token_factory_module.verify(token, config),
         {_, %{"type" => "charon_setup_challenge", "exp" => exp, "challenge" => ^challenge_name}} <-
           {:payload, payload},
         {_, false} <- {:expired, Internal.now() > exp} do
      {:ok, payload}
    else
      {:payload, _} -> {:error, "invalid token"}
      {:expired, _} -> {:error, "token expired"}
      error = {:error, <<_::binary>>} -> error
    end
  end

  @doc """
  Check a user's current password.
  """
  @spec check_current_password(map() | struct(), map, Config.t()) :: :ok | {:error, String.t()}
  def check_current_password(user, params, config) do
    %{
      password_hash_field: field,
      current_password_param: cpw_param,
      password_hashing_module: hashing_module
    } = config

    with <<cpw::binary>> <- Map.get(params, cpw_param, {:error, "#{cpw_param} not found"}),
         {:ok, _} <- hashing_module.check_pass(user, cpw, hash_key: field) do
      :ok
    end
  end

  @doc """
  Verify that the user has enabled the challenge.
  """
  @spec verify_enabled(map | struct(), String.t(), Config.t()) :: :ok | {:error, String.t()}
  def verify_enabled(user, challenge_name, config) do
    field = config.enabled_auth_challenges_field
    whitelist = Map.fetch!(user, field)

    if challenge_name in whitelist do
      :ok
    else
      {:error, "#{challenge_name} challenge not enabled for user"}
    end
  end

  ###########
  # Private #
  ###########

  @doc false
  def update_user(user, params, config) do
    config.update_user_callback.(user, params)
  end

  @doc false
  def put_enabled(user, challenge_name, config) do
    field = config.enabled_auth_challenges_field
    [challenge_name | Map.fetch!(user, field)] |> Enum.uniq()
  end

  @doc false
  def delete_enabled(user, challenge_name, config) do
    field = config.enabled_auth_challenges_field
    user |> Map.fetch!(field) |> Enum.reject(&(&1 == challenge_name))
  end
end
