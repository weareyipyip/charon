defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  defstruct [
    :created_at,
    :id,
    :type,
    :user_id,
    :expires_at,
    :refresh_token_id,
    :refreshed_at,
    extra_payload: %{}
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | nil,
          extra_payload: map(),
          id: String.t(),
          refresh_token_id: String.t(),
          refreshed_at: integer,
          type: atom(),
          user_id: pos_integer | binary()
        }

  alias Charon.{Config, Internal}

  @doc """
  Create a new session from config values and overrides.

  Provides defaults for `:id`, `:created_at` and `:expires_at`.
  """
  @spec new(Config.t(), keyword() | map()) :: t()
  def new(config, overrides \\ []) do
    now = Internal.now()

    defaults = %{
      id: Internal.random_url_encoded(16),
      created_at: now,
      expires_at: expires_at(config, now)
    }

    enum = Map.merge(defaults, Map.new(overrides))
    struct!(__MODULE__, enum)
  end

  ###########
  # Private #
  ###########

  defp expires_at(%{session_ttl: nil}, _now), do: nil
  defp expires_at(%{session_ttl: ttl}, now), do: ttl + now
end
