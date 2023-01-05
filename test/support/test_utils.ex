defmodule Charon.TestUtils do
  alias Charon.SessionStore.RedisStore

  def session_key(session_id, user_id, type \\ :full, prefix \\ "charon_"),
    do: RedisStore.session_key(session_id, user_id, type, %{key_prefix: prefix})

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  def user_sessions_key(user_id, type \\ :full, prefix \\ "charon_"),
    do: RedisStore.user_sessions_key(user_id, type, %{key_prefix: prefix})

  def conn(), do: Plug.Test.conn(:get, "/")

  @doc """
  Create a test session, with all required keys set.
  """
  def test_session(overrides \\ []) do
    %Charon.Models.Session{
      created_at: 0,
      expires_at: 0,
      id: "a",
      refresh_expires_at: 0,
      refresh_tokens: %{current_at: 0, current: [], previous: []},
      refreshed_at: 0,
      user_id: 1
    }
    |> Map.merge(Map.new(overrides))
  end
end
