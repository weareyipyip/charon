defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  @enforce_keys [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_tokens_at,
    :refresh_tokens,
    :refreshed_at,
    :user_id
  ]
  defstruct [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_tokens_at,
    :refresh_tokens,
    :refreshed_at,
    :user_id,
    extra_payload: %{},
    prev_refresh_tokens: [],
    type: :full,
    version: 3
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | :infinite,
          extra_payload: map(),
          id: String.t(),
          prev_refresh_tokens: binary(),
          refresh_expires_at: integer,
          refresh_tokens_at: integer(),
          refresh_tokens: [binary()],
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

      # old version without the :version, :refesh_expires_at, :refresh_tokens, :refresh_tokens_at, :prev_refresh_tokens fields
      # but with :__struct__ and :refresh_token_id set
      # is deserialized without error, and updated to latest version (2)
      iex> session = %{
      ...>   __struct__: Session,
      ...>   created_at: 0,
      ...>   expires_at: 1,
      ...>   extra_payload: %{},
      ...>   id: "ab",
      ...>   refresh_token_id: "cd",
      ...>   refreshed_at: 15,
      ...>   type: :full,
      ...>   user_id: 9
      ...> }
      ...> |> :erlang.term_to_binary()
      ...> |> deserialize(@charon_config)
      iex> %Session{
      ...>   created_at: 0,
      ...>   expires_at: 1,
      ...>   extra_payload: %{},
      ...>   id: "ab",
      ...>   prev_refresh_tokens: [],
      ...>   refresh_expires_at: 1,
      ...>   refresh_tokens_at: 15,
      ...>   refresh_tokens: ["cd"],
      ...>   refreshed_at: 15,
      ...>   type: :full,
      ...>   user_id: 9,
      ...>   version: 3
      ...> } = session

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
    |> update_to_v3()
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

  defp update_to_v3(session = %{refresh_tokens: _}), do: session

  defp update_to_v3(session = %{refresh_token_id: rt_id, refreshed_at: ts}) do
    session
    |> Map.drop([:refresh_token_id])
    |> Map.merge(%{version: 3, refresh_tokens: [rt_id], refresh_tokens_at: ts})
  end
end
