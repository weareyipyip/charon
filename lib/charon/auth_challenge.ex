defmodule Charon.AuthChallenge do
  @moduledoc """
  Behaviour for an authentication challenge module.
  """
  alias Charon.Config

  defmacro __using__(_opts) do
    quote do
      alias Charon.AuthChallenge
      @behaviour AuthChallenge

      def name(), do: @challenge_name

      def challenge_init(user, config) do
        AuthChallenge.verify_enabled(user, @challenge_name, config)
      end

      def setup_init(_user, conn, _config), do: {:ok, nil, conn}

      defoverridable AuthChallenge
    end
  end

  @typedoc """
  A module that implements this behaviour.
  """
  @type t :: module()

  @callback challenge_init(user :: map() | struct(), config :: Config.t()) ::
              :ok | {:error, String.t()}
  @callback challenge_complete(user :: map() | struct(), params :: map(), config :: Config.t()) ::
              :ok | {:error, String.t()}

  @callback setup_init(user :: map() | struct(), conn :: map(), config :: Config.t()) ::
              {:ok, map() | nil, map()} | {:error, String.t()}
  @callback setup_complete(user :: map() | struct(), params :: map(), config :: Config.t()) ::
              :ok | {:error, map() | String.t()}

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
