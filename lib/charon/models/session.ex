defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  @latest_version 7

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
    lock_version: 0,
    prev_tokens_fresh_from: 0,
    type: :full,
    version: @latest_version
  ]

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | :infinite,
          extra_payload: map(),
          id: String.t(),
          lock_version: integer(),
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
  Upgrade a session (or map created from a session struct) to the latest struct version (#{@latest_version}).
  """
  @spec upgrade_version(map, Config.t()) :: map
  def upgrade_version(session, config) do
    session = session |> Map.delete(:__struct__) |> update(config)
    struct!(__MODULE__, session)
  end

  ###########
  # Private #
  ###########

  defp update(session = %{version: @latest_version}, _), do: session

  # v6: no lock_version yet
  defp update(session = %{version: 6}, config) do
    session |> Map.merge(%{version: 7, lock_version: 0}) |> update(config)
  end

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
    refresh_exp = min(session.expires_at, config.refresh_token_ttl + Internal.now())
    session |> Map.merge(%{version: 2, refresh_expires_at: refresh_exp}) |> update(config)
  end

  # v0: session has no :version and may have :expires_at = nil
  defp update(session, config) do
    session
    |> Map.merge(%{version: 1, expires_at: session[:expires_at] || :infinite})
    |> update(config)
  end
end
