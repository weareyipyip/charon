defmodule Charon.TestUtils do
  alias Charon.SessionStore.RedisStore

  def session_key(session_id, user_id, prefix \\ "charon_"),
    do: RedisStore.session_key(session_id, user_id, %{key_prefix: prefix})

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  def user_sessions_key(user_id, prefix \\ "charon_"),
    do: RedisStore.user_sessions_key(user_id, %{key_prefix: prefix})

  def conn(), do: Plug.Test.conn(:get, "/")
end
