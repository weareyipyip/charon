defmodule Charon.Sessions.SessionStore do
  @moduledoc """
  Behaviour definition of a persistent session store.
  The implementation is expected to handle cleanup of expired entries.

  All three callbacks can use only a session ID, and ignore the user ID that is passed in as well, because a session ID is a unique 128-bits binary by itself. However, not ignoring the user ID enables the use case where all sessions for a user are fetched or logged out, for example, so there are benefits to storing sessions per user.
  """
  alias Charon.Sessions.Session
  alias Charon.Config

  @doc """
  Delete session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback delete(session_id :: binary, user_id :: binary | integer(), config :: Config.t()) ::
              :ok | {:error, binary}

  @doc """
  Insert or update #{Session} `session`, with time-to-live `ttl`.

  The `session_id` and `user_id` are taken from the `session` struct.
  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback upsert(session :: Session.t(), ttl :: pos_integer(), config :: Config.t()) ::
              :ok | {:error, binary}

  @doc """
  Get session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback get(session_id :: binary, user_id :: binary | integer(), config :: Config.t()) ::
              Session.t() | nil | {:error, binary}
end
