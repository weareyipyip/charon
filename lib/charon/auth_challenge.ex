defmodule Charon.AuthChallenge do
  @moduledoc """
  Behaviour for an authentication challenge module.
  """
  alias Charon.Config
  alias Plug.Conn

  defmacro __using__(_opts) do
    quote do
      alias Charon.AuthChallenge
      @behaviour AuthChallenge

      def name(), do: @challenge_name

      def challenge_init(conn, _params, user, config) do
        with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
          {:ok, conn, nil}
        else
          error -> error
        end
      end

      def setup_init(conn, _params, _user, _config), do: {:ok, conn, nil}
      def setup_complete(conn, _params, _user, _config), do: {:ok, conn, nil}

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
  This callback can be used to generate an initial challenge
  (for example to verify that the user has successfully set up an OTP app),
  store underlying secrets for the user,
  or renew a challenge's underlying secret.

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

  ###########
  # Private #
  ###########

  @doc false
  def verify_enabled(user, challenge_name, config) do
    field = config.enabled_auth_challenges_field
    whitelist = Map.fetch!(user, field)

    if challenge_name in whitelist do
      :ok
    else
      {:error, "#{challenge_name} challenge not enabled for user"}
    end
  end

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
