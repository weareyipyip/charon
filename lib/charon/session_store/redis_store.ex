defmodule Charon.SessionStore.RedisStore do
  @moduledoc """
  A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

  ## Config

  Additional config is required for this module (see `Charon.SessionStore.RedisStore.Config`):

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.SessionStore.RedisStore => %{
            redix_module: MyApp.Redix,
            key_prefix: "charon_"
          }
        }
      )

  The following options are supported:
    - `:redix_module` (required). A module that implements a `command/1` and a `pipeline/1` function for Redis commands like Redix.
    - `:key_prefix` (optional). A string prefix for the Redis keys that are sessions.

  ## Redix

  This module depends on a correctly configured `Redix` module with `command/1` and `pipeline/1` functions. See https://hexdocs.pm/redix for instructions.
  """
  @behaviour Charon.SessionStore.Behaviour
  alias Charon.Config
  alias Charon.Internal
  alias Charon.Models.Session
  import Charon.SessionStore.RedisStore.Config, only: [get_mod_config: 1]
  require Logger

  @impl true
  def get(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    session_key = session_key(session_id, user_id, type, mod_conf)

    ["GET", session_key]
    |> mod_conf.redix_module.command()
    |> case do
      {:ok, nil} -> nil
      {:ok, serialized} -> Session.deserialize(serialized, config)
      error -> error
    end
  end

  @impl true
  def upsert(session = %{id: sid, user_id: uid, refresh_expires_at: exp, type: type}, config) do
    mod_conf = get_mod_config(config)
    session_key = session_key(sid, uid, type, mod_conf)
    user_key = user_sessions_key(uid, type, mod_conf)
    exp = Integer.to_string(exp)

    [
      # start transaction
      ~W(MULTI),
      # add session key to user's sorted set, with expiration timestamp as score (or update the score)
      ["ZADD", user_key, exp, session_key],
      # add the actual session as a separate key-value pair that expires when the refresh token expires
      ["SET", session_key, Session.serialize(session), "EXAT", exp],
      ~W(EXEC)
    ]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [_, _, _, [n, "OK"]]} when is_integer(n) -> :ok
      error -> redis_result_to_error(error)
    end
    |> passthrough_maintain_session_set(user_key, mod_conf)
  end

  @impl true
  def delete(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    session_key = session_key(session_id, user_id, type, mod_conf)
    user_key = user_sessions_key(user_id, type, mod_conf)

    [
      ~W(MULTI),
      ["DEL", session_key],
      ["ZREM", user_key, session_key],
      ~W(EXEC)
    ]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [_, _, _, [n, m]]} when is_integer(n) and is_integer(m) -> :ok
      error -> redis_result_to_error(error)
    end
    |> passthrough_maintain_session_set(user_key, mod_conf)
  end

  @impl true
  def get_all(user_id, type, config) do
    mod_conf = get_mod_config(config)

    with {:ok, keys = [_ | _]} <- all_unexpired_keys(user_id, type, mod_conf),
         # get all keys with a single round trip
         {:ok, values} <- mod_conf.redix_module.command(["MGET" | keys]) do
      values |> Stream.reject(&is_nil/1) |> Enum.map(&Session.deserialize(&1, config))
    else
      {:ok, []} -> []
      other -> other
    end
  end

  @impl true
  def delete_all(user_id, type, config) do
    mod_conf = get_mod_config(config)

    with {:ok, keys} <- all_keys(user_id, type, mod_conf),
         to_delete = [user_sessions_key(user_id, type, mod_conf) | keys],
         {:ok, n} when is_integer(n) <- ["DEL" | to_delete] |> mod_conf.redix_module.command() do
      :ok
    else
      error -> redis_result_to_error(error)
    end
  end

  @doc """
  This should run periodically, for example once per day at a quiet moment.
  Deprecated; periodic cleanup is no longer required.
  """
  @spec cleanup(Config.t()) :: :ok | {:error, binary()}
  @deprecated "Periodic cleanup is no longer required."
  def cleanup(_config), do: :ok

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  ###########
  # Private #
  ###########

  # key for a single session
  # using the "old" format for :full sessions prevents old sessions from suddenly being logged-out
  # so this code is "backwards compatible" with respect to old sessions being retrievable
  @doc false
  def session_key(session_id, user_id, :full, config) do
    key = [config.key_prefix, ".s.", to_string(user_id), ?., session_id]
    :crypto.hash(:blake2s, key)
  end

  def session_key(session_id, user_id, type, config) do
    key = [config.key_prefix, ".s.", to_string(user_id), ?., Atom.to_string(type), ?., session_id]
    :crypto.hash(:blake2s, key)
  end

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  @doc false

  def user_sessions_key(user_id, :full, config),
    do: [config.key_prefix, ".u.", to_string(user_id)]

  def user_sessions_key(user_id, type, config),
    do: [config.key_prefix, ".u.", to_string(user_id), ?., Atom.to_string(type)]

  # get all keys, including expired ones, for a user
  defp all_keys(user_id, type, config) do
    # get all of the user's session keys (index 0 = first, -1 = last)
    ["ZRANGE", user_sessions_key(user_id, type, config), "0", "-1"]
    |> config.redix_module.command()
  end

  # get all valid keys for a user
  defp all_unexpired_keys(user_id, type, config) do
    now = Internal.now() |> Integer.to_string()

    # get all of the user's valid session keys (with score/timestamp >= now)
    ["ZRANGE", user_sessions_key(user_id, type, config), now, "+inf", "BYSCORE"]
    |> config.redix_module.command()
  end

  # make sure the user's session set expires at some point, and prune expired sessions from it
  defp maintain_session_set(user_key, mod_conf) do
    now = Internal.now() |> Integer.to_string()

    with {:ok, [_session_key, highest_exp]} <-
           ["ZRANGE", user_key, "+inf", "-inf", "REV", "BYSCORE", "LIMIT", "0", "1", "WITHSCORES"]
           |> mod_conf.redix_module.command(),
         {:ok, [n, m]} when is_integer(n) and is_integer(m) <-
           [
             ["EXPIREAT", user_key, highest_exp],
             ["ZREMRANGEBYSCORE", user_key, "-inf", now]
           ]
           |> mod_conf.redix_module.pipeline() do
      :ok
    else
      {:ok, []} -> :ok
      error -> Logger.error("Unexpected error #{inspect(error)}")
    end
  end

  defp passthrough_maintain_session_set(result, user_key, mod_conf) do
    maintain_session_set(user_key, mod_conf)
    result
  end

  defp redis_result_to_error({:ok, error}), do: {:error, inspect(error)}
  defp redis_result_to_error(error), do: error
end
