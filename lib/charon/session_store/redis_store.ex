defmodule Charon.SessionStore.RedisStore do
  @moduledoc """
  A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/2` and `delete_all/2` (for a user) functions.

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

  ## Cleanup

  Session keys slowly accumulate in Redis when using this store.
  It provides a `cleanup/1` that should run periodically.
  """
  @behaviour Charon.SessionStore.Behaviour
  alias Charon.Config
  alias Charon.Internal
  alias Charon.Models.Session
  require Logger

  @impl true
  def get(session_id, user_id, config) do
    config = get_module_config(config)

    ["GET", session_key(session_id, user_id, config)]
    |> config.redix_module.command()
    |> case do
      {:ok, nil} -> nil
      {:ok, serialized} -> Session.deserialize(serialized)
      error -> error
    end
  end

  @impl true
  def upsert(%{id: session_id, user_id: user_id} = session, ttl, config) do
    config = get_module_config(config)
    now = Internal.now()
    session_key = session_key(session_id, user_id, config)

    [
      # start transaction
      ~W(MULTI),
      # add session key to user's sorted set, with expiration timestamp as score (or update the score)
      ["ZADD", user_sessions_key(user_id, config), Integer.to_string(now + ttl), session_key],
      # add the actual session as a separate key-value pair with expiration ttl (or update the ttl)
      ["SET", session_key, Session.serialize(session), "EX", Integer.to_string(ttl)],
      ~W(EXEC)
    ]
    |> config.redix_module.pipeline()
    |> case do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @impl true
  def delete(session_id, user_id, config) do
    config = get_module_config(config)

    ["DEL", session_key(session_id, user_id, config)]
    |> config.redix_module.command()
    |> case do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @impl true
  def get_all(user_id, config) do
    config = get_module_config(config)

    with {:ok, keys = [_ | _]} <- all_unexpired_keys(user_id, config),
         # get all keys with a single round trip
         {:ok, values} <- config.redix_module.command(["MGET" | keys]) do
      values |> Stream.reject(&is_nil/1) |> Enum.map(&Session.deserialize/1)
    else
      {:ok, []} -> []
      other -> other
    end
  end

  @impl true
  def delete_all(user_id, config) do
    config = get_module_config(config)

    with {:ok, keys} <- all_keys(user_id, config),
         to_delete = [user_sessions_key(user_id, config) | keys],
         ["DEL" | to_delete] |> config.redix_module.command() do
      :ok
    end
  end

  @doc """
  This should run periodically, for example once per day at a quiet moment.
  """
  @spec cleanup(Config.t()) :: :ok | {:error, binary()}
  def cleanup(config) do
    config |> get_module_config() |> do_cleanup()
  end

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  ###########
  # Private #
  ###########

  defp get_module_config(%{optional_modules: %{__MODULE__ => config}}), do: config

  # key for a single session
  @doc false
  def session_key(session_id, user_id, config) do
    key = [config.key_prefix, ".s.", to_string(user_id), ?., session_id]
    :crypto.hash(:blake2s, key)
  end

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  @doc false
  def user_sessions_key(user_id, config), do: [config.key_prefix, ".u.", to_string(user_id)]

  # get all keys, including expired ones, for a user
  defp all_keys(user_id, config) do
    # get all of the user's session keys (index 0 = first, -1 = last)
    ["ZRANGE", user_sessions_key(user_id, config), "0", "-1"] |> config.redix_module.command()
  end

  # get all valid keys for a user
  defp all_unexpired_keys(user_id, config) do
    now = Internal.now() |> Integer.to_string()

    # get all of the user's valid session keys (with score/timestamp >= now)
    ["ZRANGE", user_sessions_key(user_id, config), now, "+inf", "BYSCORE"]
    |> config.redix_module.command()
  end

  defp do_cleanup(mod_conf, now \\ Internal.now() |> to_string(), cursor \\ nil, count \\ 0)

  defp do_cleanup(_mod_conf, _now, "0", count) do
    Logger.info("Removed #{count} expired session keys.")
  end

  defp do_cleanup(mod_conf, now, cursor, count) do
    ["SCAN", cursor, "MATCH", [mod_conf.key_prefix, ".u.*"]]
    |> mod_conf.redix_module.command()
    |> then(fn
      {:ok, [new_cursor | [[]]]} ->
        do_cleanup(mod_conf, now, new_cursor, count)

      {:ok, [new_cursor | [partial_results]]} ->
        partial_results
        # remove expired session keys (with score/timestamp <= now)
        |> Enum.map(&["ZREMRANGEBYSCORE", &1, "-inf", now])
        |> mod_conf.redix_module.pipeline()
        |> then(fn {:ok, deleted_counts} ->
          count = Enum.sum([count | deleted_counts])
          do_cleanup(mod_conf, now, new_cursor, count)
        end)
    end)
  end
end
