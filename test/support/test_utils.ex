defmodule Charon.TestUtils do
  alias Charon.SessionStore.RedisStore

  def session_set_key(user_id, type \\ :full, prefix \\ "charon_") do
    RedisStore.session_set_key({to_string(user_id), to_string(type), prefix})
    |> IO.iodata_to_binary()
  end

  def exp_oset_key(user_id, type \\ :full, prefix \\ "charon_") do
    RedisStore.exp_oset_key({to_string(user_id), to_string(type), prefix})
    |> IO.iodata_to_binary()
  end

  def old_session_key(session_id, user_id, type \\ :full, prefix \\ "charon_") do
    RedisStore.old_session_key(session_id, {to_string(user_id), to_string(type), prefix})
    |> IO.iodata_to_binary()
  end

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  def old_exp_oset_key(user_id, type \\ :full, prefix \\ "charon_") do
    RedisStore.old_set_key({to_string(user_id), to_string(type), prefix}) |> IO.iodata_to_binary()
  end

  def conn(), do: Plug.Test.conn(:get, "/")

  @doc """
  Create a test session, with all required keys set.
  """
  def test_session(overrides \\ []) do
    now = Charon.Internal.now()

    %Charon.Models.Session{
      created_at: now,
      expires_at: :infinite,
      id: "a",
      prev_tokens_fresh_from: 0,
      refresh_expires_at: now + 10,
      refresh_token_id: "b",
      refreshed_at: now,
      tokens_fresh_from: now,
      user_id: 1
    }
    |> Map.merge(Map.new(overrides))
  end
end
