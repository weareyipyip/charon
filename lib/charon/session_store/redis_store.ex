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
            get_signing_key: &RedisStore.default_signing_key/1
          }
        }
      )

  The following options are supported:
    - `:redix_module` (required). A module that implements a `command/1` and a `pipeline/1` function for Redis commands like Redix.
    - `:key_prefix` (optional). A string prefix for the Redis keys that are sessions.
    - `:get_signing_key` (optional). A getter/1 that returns the key that is used to sign and verify serialized session binaries.

  ## Redix

  This module depends on a correctly configured `Redix` module with `command/1` and `pipeline/1` functions. See https://hexdocs.pm/redix for instructions.
  """
  @behaviour Charon.SessionStore.Behaviour
  alias Charon.Config
  alias Charon.Internal
  import Charon.SessionStore.RedisStore.Config, only: [get_mod_config: 1]
  import Charon.Utils.{KeyGenerator, Crypto}
  require Logger

  @multi ~W(MULTI)
  @exec ~W(EXEC)

  @impl true
  def get(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    {user_id_str, type_str, key_prefix} = key_data(user_id, type, mod_conf)
    session_key = session_key(session_id, user_id_str, type_str, key_prefix)

    ["GET", session_key]
    |> mod_conf.redix_module.command()
    |> case do
      {:ok, <<serialized::binary>>} -> deserialize(serialized, mod_conf, config)
      {:ok, _} -> nil
      error -> error
    end
  end

  @impl true
  def upsert(
        session = %{
          id: sid,
          user_id: uid,
          type: type,
          refreshed_at: now,
          expires_at: s_exp,
          refresh_expires_at: exp
        },
        config
      ) do
    mod_conf = get_mod_config(config)
    {uid_str, type_str, key_prefix} = key_data(uid, type, mod_conf)
    session_key = session_key(sid, uid_str, type_str, key_prefix)
    set_key = set_key(uid_str, type_str, key_prefix)
    exp_str = Integer.to_string(exp)
    now = Integer.to_string(now)

    # upsert the actual session as a separate key-value pair that expires when the refresh token expires
    upsert_session_c = ["SET", session_key, serialize(session, mod_conf, config), "EXAT", exp_str]
    # add session key to user's session set, with exp timestamp as score (or update score)
    upsert_set_c = ["ZADD", set_key, exp_str, session_key]
    max_exp_c = get_max_exp_session_cmd(set_key)
    prune_set_c = prune_session_set_cmd(set_key, now)

    if s_exp == exp do
      # s_exp == exp, we can't assume that this session has the highest refresh exp
      # because this session's refresh_expires_at is reduced so that it is <= expires_at

      [@multi, max_exp_c, upsert_session_c, upsert_set_c, prune_set_c, @exec]
      |> mod_conf.redix_module.pipeline()
      |> case do
        {:ok, [_, _, _, _, _, [prev_max_exp_session, "OK", r3, r4]]}
        when is_integer(r3) and is_integer(r4) ->
          # prev_max_exp_session had the highest exp *before* this session was upserted
          # update user session set ttl if there is no other session OR the new session's exp is the highest
          {prev_exists?, prev_max_exp_str} = parse_zrange_withscores(prev_max_exp_session)
          prev_max_exp = String.to_integer(prev_max_exp_str)
          if not prev_exists? or exp > prev_max_exp, do: put_s_exp(set_key, exp_str, mod_conf)
          :ok

        error ->
          redis_result_to_error(error)
      end
    else
      # s_exp != exp; we can assume that this session has the highest refresh exp of all of the user's sessions
      set_exp_c = put_s_exp_cmd(set_key, exp_str)

      [@multi, upsert_session_c, upsert_set_c, set_exp_c, prune_set_c, @exec]
      |> mod_conf.redix_module.pipeline()
      |> case do
        {:ok, [_, _, _, _, _, ["OK", r2, 1, r4]]} when is_integer(r2) and is_integer(r4) -> :ok
        error -> redis_result_to_error(error)
      end
    end
  end

  @impl true
  def delete(session_id, user_id, type, config) do
    mod_conf = get_mod_config(config)
    {user_id_str, type_str, key_prefix} = key_data(user_id, type, mod_conf)
    session_key = session_key(session_id, user_id_str, type_str, key_prefix)
    set_key = set_key(user_id_str, type_str, key_prefix)
    now = Internal.now() |> Integer.to_string()

    delete_c = ["DEL", session_key]
    delete_key_c = ["ZREM", set_key, session_key]
    max_exp_c = get_max_exp_session_cmd(set_key)
    prune_set_c = prune_session_set_cmd(set_key, now)

    [@multi, max_exp_c, delete_c, delete_key_c, prune_set_c, max_exp_c, @exec]
    |> mod_conf.redix_module.pipeline()
    |> case do
      {:ok, [_, _, _, _, _, _, [pre_max_exp_session, r2, r3, _, post_max_exp_session]]}
      when is_integer(r2) and is_integer(r3) ->
        # pre_max_exp_session had the highest exp *before* this session was deleted
        {pre_exists?, pre_max_exp_str} = parse_zrange_withscores(pre_max_exp_session)
        {post_exists?, post_max_exp_str} = parse_zrange_withscores(post_max_exp_session)

        if pre_exists? and post_exists? and post_max_exp_str != pre_max_exp_str do
          put_s_exp(set_key, post_max_exp_str, mod_conf)
        end

        :ok

      error ->
        redis_result_to_error(error)
    end
  end

  @impl true
  def get_all(user_id, type, config) do
    mod_conf = get_mod_config(config)
    {user_id_str, type_str, key_prefix} = key_data(user_id, type, mod_conf)

    with {:ok, keys = [_ | _]} <-
           get_valid_session_keys(user_id_str, type_str, key_prefix, mod_conf),
         {:ok, values} <- mod_conf.redix_module.command(["MGET" | keys]) do
      values |> Stream.reject(&is_nil/1) |> Enum.map(&deserialize(&1, mod_conf, config))
    else
      {:ok, []} -> []
      other -> other
    end
  end

  @impl true
  def delete_all(user_id, type, config) do
    mod_conf = get_mod_config(config)
    {user_id_str, type_str, key_prefix} = key_data(user_id, type, mod_conf)

    with {:ok, keys} <- get_session_keys(user_id_str, type_str, key_prefix, mod_conf),
         to_delete = [set_key(user_id_str, type_str, key_prefix) | keys],
         {:ok, n} when is_integer(n) <- ["DEL" | to_delete] |> mod_conf.redix_module.command() do
      :ok
    else
      error -> redis_result_to_error(error)
    end
  end

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  @doc """
  Get the default session signing key that is used if config option `:get_signing_key` is not set explicitly.
  """
  @spec default_signing_key(Config.t()) :: binary
  def default_signing_key(config), do: derive_key(config.get_base_secret.(), "RedisStore HMAC")

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
  defp deserialize(serialized, %{get_signing_key: get_key}, config) do
    serialized
    |> verify_hmac(get_key.(config))
    |> case do
      {:ok, serialized} ->
        deserialize(serialized)

      _ ->
        Logger.warning("Ignored Redis session with invalid signature.")
        nil
    end
  end

  # deserialize a session, returning nil on errors
  defp deserialize(serialized) do
    try do
      :erlang.binary_to_term(serialized)
    rescue
      _ -> nil
    end
  end

  # key under which the actual session is stored
  @doc false
  def session_key(session_id, user_id, type, key_prefix),
    do: [key_prefix, ".s.", user_id, ?., type, ?., session_id]

  # key for the sorted-by-expiration-timestamp set of the user's session keys
  @doc false
  def set_key(user_id, "full", key_prefix), do: [key_prefix, ".u.", user_id]
  def set_key(user_id, type, key_prefix), do: [key_prefix, ".u.", user_id, ?., type]

  # get all keys, including expired ones, for a user
  defp get_session_keys(user_id, type, key_prefix, config) do
    # get all of the user's session keys (index 0 = first, -1 = last)
    ["ZRANGE", set_key(user_id, type, key_prefix), "0", "-1"]
    |> config.redix_module.command()
  end

  # get all valid keys for a user
  defp get_valid_session_keys(user_id, type, key_prefix, config) do
    now = Internal.now() |> Integer.to_string()

    # get all of the user's valid session keys (with score/timestamp >= now)
    ["ZRANGE", set_key(user_id, type, key_prefix), now, "+inf", "BYSCORE"]
    |> config.redix_module.command()
  end

  # returns {session_exists?, exp_str}
  defp parse_zrange_withscores(single_zrange_withscores_result)
  defp parse_zrange_withscores([_session_key, exp_str]), do: {true, exp_str}
  defp parse_zrange_withscores(_), do: {false, "0"}

  # clean up the user's old sessions
  defp prune_session_set_cmd(set_key, now_str), do: ["ZREMRANGEBYSCORE", set_key, "-inf", now_str]

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
      {:ok, n} when is_integer(n) -> :ok
      error -> Logger.error("Error during user session set maintenance: #{inspect(error)}")
    end
  end

  defp redis_result_to_error({:ok, error}), do: {:error, inspect(error)}
  defp redis_result_to_error(error), do: error
end
