defmodule Charon.AuthFlow.Stage do
  @moduledoc """
  A stage in an authentication flow.
  A stage consists of challenges, one of which has to be passed in order to pass the stage.
  """
  alias Charon.AuthChallenge

  @enforce_keys [:challenges]
  defstruct [:challenges]

  @typedoc """
  A set of authentication challenges, mapped to their names.
  """
  @type challenge_set :: %{required(String.t()) => AuthChallenge.t()}

  @typedoc """
  A stage in an authentication flow.
  A stage consists of challenges, one of which has to be passed in order to pass the stage.
  """
  @type t :: %__MODULE__{challenges: challenge_set()}

  @doc """
  Create a challenge set from a list of `Charon.AuthChallenge` implementing modules.
  """
  @spec list_to_challenge_set([AuthChallenge.t()]) :: challenge_set()
  def list_to_challenge_set(challenge_list) do
    Map.new(challenge_list, fn challenge -> {challenge.name(), challenge} end)
  end

  @doc """
  Get a challenge from a stage.
  """
  @spec get_challenge(t(), String.t()) :: AuthChallenge.t() | nil
  def get_challenge(_stage = %{challenges: challenges}, name), do: Map.get(challenges, name)
end
