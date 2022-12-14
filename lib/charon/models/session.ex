defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  @enforce_keys [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_token_id,
    :refreshed_at,
    :user_id
  ]
  defstruct [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_token_id,
    :refreshed_at,
    :user_id,
    extra_payload: %{},
    type: :full,
    version: 2
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | :infinite,
          extra_payload: map(),
          id: String.t(),
          refresh_expires_at: integer,
          refresh_token_id: String.t(),
          refreshed_at: integer,
          type: atom(),
          user_id: pos_integer | binary(),
          version: pos_integer
        }

  alias Charon.{Config, Internal}

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
      iex> %Session{} = test_session() |> serialize() |> deserialize(@charon_config)

      # old version without the :version and :refesh_expires_at fields but with :__struct__ set
      # is deserialized without error, and updated to latest version (2)
      iex> session = %{__struct__: Session, created_at: 0, id: "ab", user_id: 9, expires_at: 1, refresh_token_id: "cd", refreshed_at: 0, type: :full, extra_payload: %{}}
      ...> |> :erlang.term_to_binary()
      ...> |> deserialize(@charon_config)
      iex> %Session{created_at: 0, id: "ab", user_id: 9, expires_at: 1, refresh_token_id: "cd", refreshed_at: 0, type: :full, extra_payload: %{}, version: 2, refresh_expires_at: _} = session

      # old version - with :expires_at = nil - is deserialized without error
      iex> %Session{expires_at: :infinite} = test_session(expires_at: nil) |> serialize() |> deserialize(@charon_config)
  """
  @spec deserialize(binary, Config.t()) :: struct
  def deserialize(binary, config) do
    binary
    |> :erlang.binary_to_term()
    |> Map.drop([:__struct__])
    |> update_to_v1()
    |> update_to_v2(config)
    |> case do
      map -> struct!(__MODULE__, map)
    end
  end

  ###########
  # Private #
  ###########

  defp update_to_v1(session = %{expires_at: nil}),
    do: Map.merge(session, %{version: 1, expires_at: :infinite})

  defp update_to_v1(session), do: session

  defp update_to_v2(session = %{refresh_expires_at: _}, _), do: session

  defp update_to_v2(session, config) do
    exp = config.refresh_token_ttl + Internal.now()

    exp =
      if (session_exp = session.expires_at) == :infinite do
        exp
      else
        min(exp, session_exp)
      end

    Map.merge(session, %{version: 2, refresh_expires_at: exp})
  end
end
