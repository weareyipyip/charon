defmodule Charon.TestUtils do
  def session_key(session_id, user_id, prefix \\ "CHARON_SESSION_"),
    do: [prefix, ".s.", user_id, ?., session_id] |> IO.iodata_to_binary()

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  def user_sessions_key(user_id, prefix \\ "CHARON_SESSION_"),
    do: [prefix, ".u.", user_id] |> IO.iodata_to_binary()
end
