defmodule Charon.SessionStore.RedisStore do
  @moduledoc """
  A persistent session store based on Redis, which implements behaviour `Charon.SessionStore`.
  In addition to the required callbacks, this store also provides `get_all/3` and `delete_all/3` (for a user) functions.

  ## Redis requirements

  This module needs a Redis >= 8.0.0 or Valkey >= 9.0.0 instance and needs permissions to create Redis functions.
  The optimistic-locking functionality of the store was not designed with a Redis cluster in mind
  and will behave unpredictably when used with a distributed Redis deployment.
  Using a failover-replica should be fine, however.
  The Redis functions are registered with a name that includes the hashed Charon version,
  to make sure that the called function matches the expected code,
  and multiple Charon deployments can share a Redis instance.

  ## Config

  Additional config is required for this module (see `Charon.SessionStore.RedisStore.Config`):

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.SessionStore.RedisStore => %{
            key_prefix: "charon_",
            get_signing_key: &RedisStore.default_signing_key/1
          }
        }
      )

  The following options are supported:
    - `:key_prefix` (optional). A string prefix for the Redis keys that are sessions.
    - `:get_signing_key` (optional). A getter/1 that returns the key that is used to sign and verify serialized session binaries.

  ## Session signing

  In order to offer some defense-in-depth against a compromised Redis server,
  the serialized sessions are signed using a HMAC. The key is derived from the Charon
  base secret, but can be overridden in the config. This is not usually necessary, except
  when you're changing the base secret and still want to access your sessions.
  It is debatable, of course, in case your Redis server is compromised,
  if your application server holding the signing key can still be considered secure.
  However, given that there are no real drawbacks to using signed session binaries,
  since the performance cost is negligible, no extra config is needed, it is easy to implement,
  and defense-in-depth is a good guiding principle, RedisStore implements this feature anyway.

  ## Implementation details

  RedisStore stores sessions until their associated refresh token(s) expire.
  That means that `:refresh_expires_at` is used to determine if a session is "alive",
  not `:expires_at`.
  This makes sense, because a session without a valid refresh token is effectively useless,
  and it means we can support "infinite lifetime" sessions while still pruning sessions that aren't used.
  This is one reason to set `:refresh_ttl` to a limited value, no more than six months is recommended.

  Last but not least, [Redis 7 functions](https://redis.io/docs/manual/programmability/functions-intro/)
  are used to implement some features, specifically optimistic locking, and to ensure all callbacks
  use only a single round-trip to the Redis instance.
  """
  alias Charon.SessionStore.Behaviour, as: SessionStoreBehaviour
  use Charon.OptMod
  @behaviour SessionStoreBehaviour
  alias Charon.{Config, Utils, Internal}
  alias __MODULE__.{LuaFunctions}
  alias Utils.{KeyGenerator, PersistentTermCache}

  import Internal.Crypto
  require Logger

  # Implementation goals:
  #  - single round-trip implementations of all callbacks
  #  - no cleanup/0 or equivalent required (all keys eventually expire)
  #  - optimistic locking support (when get-then-updating a session)
  #  - defense-in-depth against a compromised redis server by signing serialized session binaries
  #
  # In order to achieve these goals, we store sessions in a hashset with expiring subkeys:
  #   sid -> session
  #   l.sid -> lock version
  #
  # We check the lock and update the session+lock atomically using a Redis function.

  @lock_key_prefix "l."

  def register_lua_functions(config) do
    mod_conf = get_mod_conf!(config)
    %{expected_result: res, cmd: cmd} = LuaFunctions.register_functions_cmd()
    {:ok, ^res} = mod_conf.redis_client_module.command(cmd)
  end

  @impl SessionStoreBehaviour
  def get(session_id, user_id, type, config) do
    mod_conf = get_mod_conf!(config)
    session_set_key = session_set_key(user_id, type, mod_conf)
    signing_key = get_signing_key(mod_conf, config)

    ["HGET", session_set_key, session_id]
    |> mod_conf.redis_client_module.command()
    |> case do
      {:ok, nil_or_binary} ->
        nil_or_binary
        |> verify_signature(signing_key)
        |> maybe_deserialize()
        |> verify_payload(session_id, user_id, type, Internal.now())

      error ->
        error
    end
  end

  @impl SessionStoreBehaviour
  def upsert(
        session = %{id: sid, lock_version: lock, refresh_expires_at: exp, refreshed_at: now},
        config
      )
      when exp >= now do
    mod_conf = get_mod_conf!(config)
    session_set_key = session_set_key(session.user_id, session.type, mod_conf)
    lock_key = lock_key(sid)
    signing_key = get_signing_key(mod_conf, config)

    new_lock = lock + 1
    session = %{session | lock_version: new_lock}
    signed = session |> serialize() |> sign_hmac(signing_key)

    LuaFunctions.opt_lock_upsert_cmd(session_set_key, sid, lock_key, new_lock, signed, exp)
    |> mod_conf.redis_client_module.command()
    |> case do
      {:ok, "CONFLICT"} -> {:error, :conflict}
      {:ok, 1} -> :ok
      error -> redis_result_to_error(error)
    end
  end

  def upsert(_, _), do: :ok

  @impl SessionStoreBehaviour
  def delete(session_id, user_id, type, config) do
    mod_conf = get_mod_conf!(config)
    session_set_key = session_set_key(user_id, type, mod_conf)
    lock_key = lock_key(session_id)

    ["HDEL", session_set_key, session_id, lock_key]
    |> mod_conf.redis_client_module.command()
    |> case do
      {:ok, _} -> :ok
      error -> redis_result_to_error(error)
    end
  end

  @impl SessionStoreBehaviour
  def get_all(user_id, type, config) do
    mod_conf = get_mod_conf!(config)
    session_set_key = session_set_key(user_id, type, mod_conf)
    signing_key = get_signing_key(mod_conf, config)
    now = Internal.now()

    with {:ok, values} <- mod_conf.redis_client_module.command(["HGETALL", session_set_key]) do
      values
      |> Stream.chunk_every(2)
      |> Stream.reject(&is_lock?/1)
      |> Stream.map(fn [_sid, nil_or_binary] ->
        nil_or_binary
        |> verify_signature(signing_key)
        |> maybe_deserialize()
        |> verify_payload(user_id, type, now)
      end)
      |> Enum.reject(&is_nil/1)
    end
  end

  @impl SessionStoreBehaviour
  def delete_all(user_id, type, config) do
    mod_conf = get_mod_conf!(config)
    session_set_key = session_set_key(user_id, type, mod_conf)

    with {:ok, _} <- mod_conf.redis_client_module.command(["DEL", session_set_key]) do
      :ok
    else
      error -> redis_result_to_error(error)
    end
  end

  @doc """
  Get the default session signing key that is used if config option `:get_signing_key` is not set explicitly.
  """
  @spec default_signing_key(Config.t()) :: binary
  def default_signing_key(config) do
    PersistentTermCache.get_or_create(__MODULE__, fn ->
      KeyGenerator.derive_key(config.base_secret, "RedisStore HMAC")
    end)
  end

  @impl OptMod
  def init_config(config) do
    mod_conf = get_mod_conf(config)
    mod_conf = struct!(__MODULE__.Config, mod_conf)
    Charon.OptMod.put_mod_conf(config, __MODULE__, mod_conf)
  end

  ###########
  # Private #
  ###########

  defp serialize(session), do: :erlang.term_to_binary(session)

  @doc false
  def get_signing_key(%{get_signing_key: get_key}, config), do: get_key.(config)

  @doc false
  # verify the prefixed hmac of a binary
  def verify_signature(nil, _), do: nil
  def verify_signature(serialized, key), do: verify_hmac(serialized, key)

  @doc false
  # deserialize the result of verify/3, when valid
  def maybe_deserialize({:ok, verified}), do: :erlang.binary_to_term(verified)
  def maybe_deserialize(nil), do: nil

  def maybe_deserialize(_) do
    Logger.warning("Ignored Redis session with invalid signature.")
    nil
  end

  # validate that session matches uid, type and is not expired
  defp verify_payload(session, uid, type, now) do
    case session do
      s = %{refresh_expires_at: exp, user_id: ^uid, type: ^type} when exp >= now -> s
      _ -> nil
    end
  end

  # validate that session matches sid, uid, type and is not expired
  defp verify_payload(session, sid, uid, type, now) do
    case verify_payload(session, uid, type, now) do
      s = %{id: ^sid} -> s
      _ -> nil
    end
  end

  @doc false
  @compile {:inline, [session_set_key: 3]}
  def session_set_key(uid, type, mod_conf) when is_binary(uid) do
    [mod_conf.key_prefix, ?., uid, ?., Atom.to_string(type)]
  end

  def session_set_key(uid, type, mod_conf), do: session_set_key(to_string(uid), type, mod_conf)

  @doc false
  @compile {:inline, [lock_key: 1]}
  def lock_key(sid), do: [@lock_key_prefix, sid]

  # transforms an {:ok, _} result into an {:error, _} result
  defp redis_result_to_error({:ok, error}), do: {:error, inspect(error)}
  defp redis_result_to_error(error), do: error

  defp is_lock?([_key = @lock_key_prefix <> _sid, _value]), do: true
  defp is_lock?(_), do: false
end
