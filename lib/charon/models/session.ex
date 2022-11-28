defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  @enforce_keys [:expires_at]
  defstruct [
    :created_at,
    :id,
    :user_id,
    :expires_at,
    :refresh_token_id,
    :refreshed_at,
    type: :full,
    extra_payload: %{},
    version: 1
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | :infinite,
          extra_payload: map(),
          id: String.t(),
          refresh_token_id: String.t(),
          refreshed_at: integer,
          type: atom(),
          user_id: pos_integer | binary(),
          version: pos_integer
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

  @doc """
  Serialize a session.
  """
  @spec serialize(struct) :: binary
  def serialize(session) do
    session |> Map.from_struct() |> :erlang.term_to_binary()
  end

  @doc """
  Deserialize a session, without breaking for structural changes in the session struct.

  ## DocTests

      @charon_config Charon.Config.from_enum(token_issuer: "local")

      # serialization is reversible
      iex> %Session{} = @charon_config |> new() |> serialize() |> deserialize()

      # old version - without the :version field but with :__struct__ set - is deserialized without error
      iex> %{__struct__: Session, created_at: 0, id: "ab", user_id: 9, expires_at: 1, refresh_token_id: "cd", refreshed_at: 0, type: :full, extra_payload: %{}}
      ...> |> :erlang.term_to_binary()
      ...> |> deserialize()
      %Session{created_at: 0, id: "ab", user_id: 9, expires_at: 1, refresh_token_id: "cd", refreshed_at: 0, type: :full, extra_payload: %{}, version: 1}

      # old version - with :expires_at = nil - is deserialized without error
      iex> %Session{expires_at: :infinite} = @charon_config |> new(expires_at: nil) |> serialize() |> deserialize()
  """
  @spec deserialize(binary) :: struct
  def deserialize(binary) do
    binary
    |> :erlang.binary_to_term()
    |> Map.drop([:__struct__])
    |> case do
      session = %{expires_at: nil} -> %{session | expires_at: :infinite}
      session -> session
    end
    |> case do
      map -> struct!(__MODULE__, map)
    end
  end

  ###########
  # Private #
  ###########

  defp expires_at(%{session_ttl: :infinite}, _now), do: :infinite
  defp expires_at(%{session_ttl: nil}, _now), do: :infinite
  defp expires_at(%{session_ttl: ttl}, now), do: ttl + now
end
