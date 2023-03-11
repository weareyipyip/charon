defmodule Charon.SessionStore.Behaviour do
  @moduledoc """
  Behaviour definition of a persistent session store.
  Clients should not use the implementation directly, but should use `Charon.SessionStore`.

  Implementations are expected to store sessions by ID, user ID and session type.
  For the optional callbacks `get_all/3` and `delete_all/3`, sessions should be retrievable
  by user ID and session type only.

  Implementations should return the session exactly as it went in
  (they don't have to take care of struct version upgrades).

  Implementations should handle cleanup of expired entries,
  but may define additional functions and instructions to take care of such things
  (like a `cleanup/0` that should run periodically).
  """
  alias Charon.{Session, Config}

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

  Implementations may assume that `Charon.SessionPlugs.upsert_session/3` will ensure that:
   - `:refreshed_at` contains the current unix timestamp
   - `:refresh_expires_at` never exceeds `:expires_at`
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
