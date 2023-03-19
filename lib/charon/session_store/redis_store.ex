defmodule Charon.SessionStore.RedisStore do
  @moduledoc """
  A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

  ## Redis requirements

  This module needs a Redis >= 6.2.0 instance.

  ## Config

  Additional config is required for this module (see `Charon.SessionStore.RedisStore.Config`):

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.SessionStore.RedisStore => %{
            redix_module: MyApp.Redix,
            key_prefix: "charon_",
            get_signing_key: &RedisStore.default_signing_key/1,
            allow_unsigned?: true
          }
        }
      )

  The following options are supported:
    - `:redix_module` (required). A module that implements a `command/1` and a `pipeline/1` function for Redis commands like Redix.
    - `:key_prefix` (optional). A string prefix for the Redis keys that are sessions.
    - `:get_signing_key` (optional). A getter/1 that returns the key that is used to sign and verify serialized session binaries.
    - `:allow_unsigned?` (optional). Allow unsigned sessions for legacy reasons. This option will be removed and no unsigned session will be allowed anymore in a future major release.

  ## Redix

  This module depends on a correctly configured `Redix` module with `command/1` and `pipeline/1` functions. See https://hexdocs.pm/redix for instructions.
  """
  @behaviour Charon.SessionStore.Behaviour
  alias Charon.{Config, Internal, Utils}
  import Charon.SessionStore.RedisStore.Config, only: [get_mod_config: 1]
  import Utils.{KeyGenerator}
  import Internal.Crypto
  require Logger

  @multi ~W(MULTI)
  @exec ~W(EXEC)

  @impl true
  def get(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    key_data = key_data(user_id, type, mod_conf)
    session_set_key = session_set_key(key_data)
    oldest_session_key = oldest_session_key(session_id, key_data)
    old_session_key = old_session_key(session_id, key_data)

    [
      ["HGET", session_set_key, session_id],
      ["MGET", old_session_key, oldest_session_key]
    ]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [h_result, m_results]} ->
        Enum.find_value([h_result | m_results], &deserialize(&1, mod_conf, config))
        |> validate(session_id, user_id, type, Internal.now())

      error ->
        error
    end
  end

  @impl true
  def upsert(_session = %{refresh_expires_at: exp, refreshed_at: now}, _config) when exp < now,
    do: :ok

  def upsert(
        session = %{
          id: sid,
          user_id: uid,
          type: type,
          refreshed_at: now,
          refresh_expires_at: exp
        },
        config
      ) do
    mod_conf = get_mod_config(config)
    key_data = key_data(uid, type, mod_conf)
    session_set_key = session_set_key(key_data)
    exp_oset_key = exp_oset_key(key_data)
    exp_str = Integer.to_string(exp)
    now = Integer.to_string(now)

    serialized = serialize(session, mod_conf, config)
    new_upsert_c = ["HSET", session_set_key, sid, serialized]
    exp_new_upsert_c = ["EXPIRE", session_set_key, to_string(config.refresh_token_ttl)]
    new_exp_oset_c = ["ZADD", exp_oset_key, exp_str, sid]
    exp_new_exp_oset_c = ["EXPIRE", exp_oset_key, to_string(config.refresh_token_ttl)]

    # cleanup old format sessions on new format upsert
    oldest_session_key = oldest_session_key(sid, key_data)
    old_session_key = old_session_key(sid, key_data)
    old_set_key = old_set_key(key_data)
    del_old_c = ["DEL", old_session_key, oldest_session_key]
    del_old_oset_c = ["ZREM", old_set_key, old_session_key, oldest_session_key]
    prune_old_c = prune_session_set_cmd(old_set_key, now)

    [
      @multi,
      new_upsert_c,
      exp_new_upsert_c,
      new_exp_oset_c,
      exp_new_exp_oset_c,
      del_old_c,
      del_old_oset_c,
      prune_old_c,
      @exec
    ]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [_, _, _, _, _, _, _, _, [_, _, _, _, _, _, _]]} -> :ok
      error -> redis_result_to_error(error)
    end
    |> tap(fn _ ->
      prune_new_sessions(exp_oset_key, session_set_key, now, mod_conf)
    end)
  end

  @impl true
  def delete(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    key_data = key_data(user_id, type, mod_conf)
    oldest_session_key = oldest_session_key(session_id, key_data)
    old_session_key = old_session_key(session_id, key_data)
    session_set_key = session_set_key(key_data)
    exp_oset_key = exp_oset_key(key_data)
    old_set_key = old_set_key(key_data)

    del_c = ["DEL", old_session_key, oldest_session_key]
    del_old_oset_c = ["ZREM", old_set_key, old_session_key, oldest_session_key]
    del_oset_c = ["ZREM", exp_oset_key, session_id]
    del_session_set_c = ["HDEL", session_set_key, session_id]
    max_exp_c = get_max_exp_session_cmd(old_set_key)

    [@multi, max_exp_c, del_c, del_old_oset_c, del_oset_c, del_session_set_c, max_exp_c, @exec]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [_, _, _, _, _, _, _, [pre_max_exp_session, _, _, _, _, post_max_exp_session]]} ->
        # pre_max_exp_session had the highest exp *before* this session was deleted
        {pre_exists?, pre_max_exp_str} = parse_zrange_withscores(pre_max_exp_session)
        {post_exists?, post_max_exp_str} = parse_zrange_withscores(post_max_exp_session)

        if pre_exists? and post_exists? and post_max_exp_str != pre_max_exp_str do
          put_s_exp(old_set_key, post_max_exp_str, mod_conf)
          put_s_exp(exp_oset_key, post_max_exp_str, mod_conf)
        end

        :ok

      error ->
        redis_result_to_error(error)
    end
  end

  @impl true
  def get_all(user_id, type, config) do
    mod_conf = get_mod_config(config)
    key_data = key_data(user_id, type, mod_conf)
    session_set_key = session_set_key(key_data)
    now = Internal.now()

    with {:ok, keys} <- get_valid_session_keys(key_data, mod_conf),
         {:ok, values} <-
           [["HVALS", session_set_key]]
           |> then(fn commands ->
             case keys do
               [] -> commands
               _ -> [["MGET" | keys] | commands]
             end
           end)
           |> mod_conf.redix_module.pipeline() do
      values
      |> List.flatten()
      |> Stream.map(&deserialize(&1, mod_conf, config))
      |> Stream.map(&validate(&1, user_id, type, now))
      |> Enum.reject(&is_nil/1)
    end
  end

  @impl true
  def delete_all(user_id, type, config) do
    mod_conf = get_mod_config(config)
    key_data = key_data(user_id, type, mod_conf)
    session_set_key = session_set_key(key_data)
    exp_oset_key = exp_oset_key(key_data)
    old_set_key = old_set_key(key_data)

    with {:ok, keys} <- get_session_keys(key_data, mod_conf),
         to_delete = [old_set_key, session_set_key, exp_oset_key | keys],
         {:ok, _} <- ["DEL" | to_delete] |> mod_conf.redix_module.command() do
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

  @doc """
  Get the default session signing key that is used if config option `:get_signing_key` is not set explicitly.
  """
  @spec default_signing_key(Config.t()) :: binary
  def default_signing_key(config), do: derive_key(config.get_base_secret.(), "RedisStore HMAC")

  @doc """
  Migrate sessions to new storage format:
   - keys no longer hashed
   - sessions are signed
  """
  @spec migrate_sessions(Config.t()) :: :ok
  def migrate_sessions(config) do
    mod_conf = get_mod_config(config)
    mod_conf = %{mod_conf | allow_unsigned?: true}
    redix = mod_conf.redix_module

    find_session_sets(config, mod_conf, [], nil)
    |> Stream.chunk_every(50)
    # [u1_set, u2_set]
    |> Enum.each(fn session_set_keys ->
      session_set_keys
      |> Enum.map(&["ZRANGE", &1, "-inf", "+inf", "BYSCORE"])
      |> redix.pipeline()
      # [[u1.a, u1.b], [u2.c]]
      |> then(fn {:ok, list_of_lists_of_session_keys} ->
        session_keys = List.flatten(list_of_lists_of_session_keys)

        {:ok, sessions} = redix.command(["MGET" | session_keys])
        redix.command(["DEL" | session_keys ++ session_set_keys])

        sessions
        |> Stream.reject(&is_nil/1)
        |> Stream.map(&deserialize(&1, mod_conf, config))
        |> Stream.reject(&is_nil/1)
        |> Stream.map(&Charon.Models.Session.upgrade_version(&1, config))
        # on upsert, every session is signed and inserted with the new key format
        |> Enum.each(&upsert(&1, config))
      end)
    end)
  end

  ###########
  # Private #
  ###########

  defp key_data(uid, type, mod_conf),
    do: {to_string(uid), Atom.to_string(type), mod_conf.key_prefix}

  # serialize and sign a session
  defp serialize(session, %{get_signing_key: get_key}, config) do
    session |> :erlang.term_to_binary() |> sign_hmac(get_key.(config))
  end

  # deserialize session and verify its signature
  defp deserialize(nil, _, _), do: nil

  defp deserialize(serialized, %{get_signing_key: get_key, allow_unsigned?: unsigned?}, config) do
    serialized |> verify_hmac(get_key.(config)) |> on_verify_hmac(unsigned?, serialized)
  end

  # if (signature verified OR allow_unsigned?) AND session could be deserialized, return it
  # else return nil
  defp on_verify_hmac({:ok, serialized}, _, _), do: deserialize(serialized)

  defp on_verify_hmac({_, :malformed_input}, true, serialized) do
    serialized
    |> deserialize()
    |> tap(fn s -> s && Logger.warning("Unsigned session #{s.id} fetched from Redis.") end)
  end

  # signature is invalid or session isn't signed and this isn't allowed
  defp on_verify_hmac(_, _, _) do
    Logger.warning("Ignored Redis session with invalid signature.")
    nil
  end

  # deserialize a session, returning nil on errors
  defp deserialize(serialized) do
    try do
      :erlang.binary_to_term(serialized)
    rescue
      _ -> nil
    end
  end

  # old key for a single session
  # using the "old" format for :full sessions prevents old sessions from suddenly being logged-out
  # so this code is "backwards compatible" with respect to old sessions being retrievable
  @doc false
  def oldest_session_key(session_id, {user_id, "full", key_prefix}),
    do: :crypto.hash(:blake2s, [key_prefix, ".s.", user_id, ?., session_id])

  def oldest_session_key(session_id, {user_id, type, key_prefix}),
    do: :crypto.hash(:blake2s, [key_prefix, ".s.", user_id, ?., type, ?., session_id])

  # session key. The session ID is assumed to be a unique value.
  @doc false
  def old_session_key(session_id, {user_id, type, key_prefix}),
    do: [key_prefix, ".s.", user_id, ?., type, ?., session_id]

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  @doc false
  def old_set_key({user_id, "full", key_prefix}), do: [key_prefix, ".u.", user_id]
  def old_set_key({user_id, type, key_prefix}), do: [key_prefix, ".u.", user_id, ?., type]

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  @doc false
  # the expiration ordered set stores sids and expiration timestamps sorted by the timestamp
  def exp_oset_key({uid, type, prefix}), do: to_key(uid, type, prefix, "e")

  @doc false
  # the session set maps sid's to sessions
  def session_set_key({uid, type, prefix}), do: to_key(uid, type, prefix, "se")

  # create a key from a user_id, sessions type, prefix, and separator
  defp to_key(uid, type, prefix, sep), do: [prefix, ?., sep, ?., uid, ?., type]

  # get all keys, including expired ones, for a user
  defp get_session_keys(key_data, config) do
    # get all of the user's session keys (index 0 = first, -1 = last)
    ["ZRANGE", old_set_key(key_data), "0", "-1"]
    |> config.redix_module.command()
  end

  # get all valid keys for a user
  defp get_valid_session_keys(key_data, config) do
    now = Internal.now() |> Integer.to_string()

    # get all of the user's valid session keys (with score/timestamp >= now)
    ["ZRANGE", old_set_key(key_data), now, "+inf", "BYSCORE"]
    |> config.redix_module.command()
  end

  # returns {session_exists?, exp_str}
  defp parse_zrange_withscores(single_zrange_withscores_result)
  defp parse_zrange_withscores([_session_key, exp_str]), do: {true, exp_str}
  defp parse_zrange_withscores(_), do: {false, "0"}

  # clean up the user's old sessions
  defp prune_session_set_cmd(set_key, now_str),
    do: ["ZREMRANGEBYSCORE", set_key, "-inf", now_str]

  # grab the session key and score (= exp timestamp) of the highest-exp session of the user
  defp get_max_exp_session_cmd(set_key) do
    ["ZRANGE", set_key, "+inf", "-inf", "REV", "BYSCORE", "LIMIT", "0", "1", "WITHSCORES"]
  end

  # set the expiration time of the user's session set
  defp put_s_exp_cmd(set_key, exp_str), do: ["EXPIREAT", set_key, exp_str]

  defp put_s_exp(set_key, exp_str, mod_conf) do
    put_s_exp_cmd(set_key, exp_str)
    |> mod_conf.redix_module.command()
    |> case do
      {:ok, _} -> :ok
      error -> Logger.error("Error during user session set maintenance: #{inspect(error)}")
    end
  end

  defp redis_result_to_error({:ok, error}), do: {:error, inspect(error)}
  defp redis_result_to_error(error), do: error

  defp find_session_sets(_config, _mod_conf, set_keys, "0"), do: set_keys

  defp find_session_sets(config, mod_conf, set_keys, cursor) do
    ["SCAN", cursor, "MATCH", [mod_conf.key_prefix, ".u.*"]]
    |> mod_conf.redix_module.command()
    |> then(fn {:ok, [new_cursor | [partial_results]]} ->
      find_session_sets(config, mod_conf, set_keys ++ partial_results, new_cursor)
    end)
  end

  defp prune_new_sessions(exp_oset_key, session_set_key, now, mod_conf) do
    with {:ok, expired = [_ | _]} <-
           mod_conf.redix_module.command(["ZRANGE", exp_oset_key, "-inf", "(#{now}", "BYSCORE"]),
         {:ok, _} <-
           mod_conf.redix_module.pipeline([
             ["ZREM", exp_oset_key, expired],
             ["HDEL", session_set_key, expired]
           ]) do
      :ok
    else
      {:ok, []} -> :ok
      other -> Logger.error(inspect(other))
    end
  end

  # validate that session matches uid, type and is not expired
  defp validate(session, uid, type, now) do
    case session do
      s = %{refresh_expires_at: exp, user_id: ^uid, type: ^type} when exp >= now -> s
      _ -> nil
    end
  end

  # validate that session matches sid, uid, type and is not expired
  defp validate(session, sid, uid, type, now) do
    case validate(session, uid, type, now) do
      s = %{id: ^sid} -> s
      _ -> nil
    end
  end
end
