defmodule Charon.SessionStore.Behaviour do
  @moduledoc """
  Behaviour definition of a persistent session store.
  The implementation is expected to handle cleanup of expired entries.

  Implementations are expected to store sessions by ID, user ID and session type.
  For the optional callbacks `get_all/3` and `delete_all/3`, sessions should be retrievable
  by user ID and session type only.
  """
  alias Charon.Session
  alias Charon.Config

  @optional_callbacks [get_all: 3, delete_all: 3]

  @doc """
  Delete session of type `type` with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback delete(
              session_id :: binary,
              user_id :: binary | integer(),
              type :: atom(),
              config :: Config.t()
            ) ::
              :ok | {:error, binary}

  @doc """
  Insert or update `session`.

  Values `session_id`, `user_id` and `type` are taken from the `session` struct.
  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback upsert(session :: Session.t(), config :: Config.t()) :: :ok | {:error, binary}

  @doc """
  Get session of type `type` with id `session_id` for user with id `user_id`.
  Must not return sessions that have expired,
  or that can't be refreshed anymore because the refresh token has expired.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback get(
              session_id :: binary,
              user_id :: binary | integer(),
              type :: atom(),
              config :: Config.t()
            ) ::
              Session.t() | nil | {:error, binary}

  @doc """
  Get all sessions of type `type` for the user with id `user_id`.
  Must not return sessions that have expired,
  or that can't be refreshed anymore because the refresh token has expired.
  """
  @callback get_all(user_id :: binary | integer, type :: atom(), config :: Config.t()) ::
              [Session.t()] | {:error, binary}

  @doc """
  Delete all sessions of type `type` for the user with id `user_id`.
  """
  @callback delete_all(user_id :: binary | integer, type :: atom(), config :: Config.t()) ::
              :ok | {:error, binary}
end
