defmodule Charon.SessionStore.Behaviour do
  @moduledoc """
  Behaviour definition of a persistent session store.
  The implementation is expected to handle cleanup of expired entries.

  All three callbacks can use only a session ID, and ignore the user ID that is passed in as well, because a session ID is a unique 128-bits binary by itself.

  However, not ignoring the user ID enables the usecase where all sessions for a user are fetched or deleted (the optional callbacks), for example, so there are benefits to storing sessions per user.
  """
  alias Charon.Session
  alias Charon.Config

  @optional_callbacks [get_all: 2, delete_all: 2]

  @doc """
  Delete session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback delete(session_id :: binary, user_id :: binary | integer(), config :: Config.t()) ::
              :ok | {:error, binary}

  @doc """
  Insert or update `session`.

  The `session_id` and `user_id` are taken from the `session` struct.
  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback upsert(session :: Session.t(), config :: Config.t()) :: :ok | {:error, binary}

  @doc """
  Get session with id `session_id` for user with id `user_id`.
  Must not return sessions that have expired,
  or that can't be refreshed anymore because the refresh token has expired.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback get(session_id :: binary, user_id :: binary | integer(), config :: Config.t()) ::
              Session.t() | nil | {:error, binary}

  @doc """
  Get all sessions for the user with id `user_id`.
  Must not return sessions that have expired,
  or that can't be refreshed anymore because the refresh token has expired.
  """
  @callback get_all(user_id :: binary | integer, config :: Config.t()) ::
              [Session.t()] | {:error, binary}

  @doc """
  Delete all sessions for the user with id `user_id`.
  """
  @callback delete_all(user_id :: binary | integer, config :: Config.t()) ::
              :ok | {:error, binary}
end
