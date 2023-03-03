defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  @latest_version 6

  @enforce_keys [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_token_id,
    :refreshed_at,
    :tokens_fresh_from,
    :user_id
  ]
  defstruct [
    :created_at,
    :expires_at,
    :id,
    :refresh_expires_at,
    :refresh_token_id,
    :refreshed_at,
    :tokens_fresh_from,
    :user_id,
    extra_payload: %{},
    prev_tokens_fresh_from: 0,
    type: :full,
    version: @latest_version
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | :infinite,
          extra_payload: map(),
          id: String.t(),
          prev_tokens_fresh_from: integer,
          refresh_expires_at: integer,
          refresh_token_id: binary(),
          refreshed_at: integer,
          tokens_fresh_from: integer,
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

      # old version without the :version, :refesh_expires_at fields but with :__struct__ set
      # is deserialized without error, and updated to latest version (#{@latest_version})
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
      ...>   prev_tokens_fresh_from: 0,
      ...>   refresh_expires_at: 1,
      ...>   refresh_token_id: "cd",
      ...>   refreshed_at: 15,
      ...>   tokens_fresh_from: 15,
      ...>   type: :full,
      ...>   user_id: 9,
      ...>   version: #{@latest_version}
      ...> } = session

      # old version - with :expires_at = nil - is deserialized without error
      iex> session = %{
      ...>   __struct__: Session,
      ...>   created_at: 0,
      ...>   expires_at: nil,
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
      ...>   expires_at: :infinite,
      ...>   extra_payload: %{},
      ...>   id: "ab",
      ...>   prev_tokens_fresh_from: 0,
      ...>   refresh_expires_at: refresh_exp,
      ...>   refresh_token_id: "cd",
      ...>   refreshed_at: 15,
      ...>   tokens_fresh_from: 15,
      ...>   type: :full,
      ...>   user_id: 9,
      ...>   version: #{@latest_version}
      ...> } = session
      iex> refresh_exp > 100000
      true
  """
  @spec deserialize(binary, Config.t()) :: struct
  def deserialize(binary, config) do
    binary
    |> :erlang.binary_to_term()
    |> Map.drop([:__struct__])
    |> update(config)
    |> case do
      map -> struct!(__MODULE__, map)
    end
  end

  ###########
  # Private #
  ###########

  defp update(session = %{version: @latest_version}, _), do: session

  # v5: tokens_fresh_from was still called t_gen_fresh_at, which is less descriptive
  defp update(session = %{version: 5, prev_t_gen_fresh_at: p, t_gen_fresh_at: c}, config) do
    session
    |> Map.drop([:prev_t_gen_fresh_at, :t_gen_fresh_at])
    |> Map.merge(%{version: 6, prev_tokens_fresh_from: p, tokens_fresh_from: c})
    |> update(config)
  end

  # v4: session has no :t_gen_fresh_at or :prev_t_gen_fresh_at
  defp update(session = %{version: 4, refreshed_at: refreshed_at}, config) do
    session
    |> Map.merge(%{version: 5, prev_t_gen_fresh_at: 0, t_gen_fresh_at: refreshed_at})
    |> update(config)
  end

  # v3: session still has :refresh_tokens, :refresh_tokens_at and :prev_refresh_tokens
  defp update(session = %{version: 3, refresh_tokens: rt_ids}, config) do
    session
    |> Map.drop([:refresh_tokens, :refresh_tokens_at, :prev_refresh_tokens])
    |> Map.merge(%{version: 4, refresh_token_id: List.first(rt_ids, "unknown")})
    |> update(config)
  end

  # v2: we're back to v2 in v4, so we can jump to it immediately
  defp update(session = %{version: 2}, config), do: %{session | version: 4} |> update(config)

  # v1: session has no :refresh_expires_at
  defp update(session = %{version: 1}, config) do
    exp = config.refresh_token_ttl + Internal.now()

    exp =
      if (session_exp = session.expires_at) == :infinite do
        exp
      else
        min(exp, session_exp)
      end

    session |> Map.merge(%{version: 2, refresh_expires_at: exp}) |> update(config)
  end

  # v0: session has no :version and may have :expires_at = nil
  defp update(session, config) do
    session
    |> Map.merge(%{version: 1, expires_at: session[:expires_at] || :infinite})
    |> update(config)
  end
end
