defmodule Charon.SessionStore.RedisStore do
  @moduledoc """
  A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/2` and `delete_all/2` (for a user) functions.

  ## Config

  Additional config is required for this module:

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
  @behaviour Charon.SessionStore
  alias Charon.Config
  alias Charon.Internal

  @impl true
  def get(session_id, user_id, config) do
    config = get_module_config(config)

    ["GET", session_key(session_id, user_id, config)]
    |> config.redix_module.command()
    |> case do
      {:ok, nil} -> nil
      {:ok, serialized} -> :erlang.binary_to_term(serialized)
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
      ["SET", session_key, :erlang.term_to_binary(session), "EX", Integer.to_string(ttl)],
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
      values |> Stream.reject(&is_nil/1) |> Enum.map(&:erlang.binary_to_term/1)
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
    config = get_module_config(config)
    now = Internal.now() |> Integer.to_string()

    with {:ok, set_keys = [_ | _]} <- scan([config.key_prefix, ".u.*"], config) do
      set_keys
      |> Stream.chunk_every(500)
      |> Stream.map(fn set_of_user_session_sets ->
        set_of_user_session_sets
        # remove expired session keys (with score/timestamp <= now)
        |> Enum.map(&["ZREMRANGEBYSCORE", &1, "-inf", now])
        |> config.redix_module.pipeline()
      end)
      |> Enum.find(:ok, &match?({:error, _}, &1))
    end
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

  # scan the redis keyspace for a pattern
  defp scan(pattern, config, iteration \\ nil, results \\ MapSet.new())
  defp scan(_pattern, _config, "0", results), do: {:ok, MapSet.to_list(results)}

  defp scan(pattern, config, iteration, results) do
    ["SCAN", iteration, "MATCH", pattern]
    |> config.redix_module.command()
    |> case do
      {:ok, [iteration | [partial_results]]} ->
        partial_results = MapSet.new(partial_results)
        results = MapSet.union(results, partial_results)
        scan(pattern, config, iteration, results)

      error ->
        error
    end
  end
end
