if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore.StoreImpl do
    @moduledoc false
    alias Charon.SessionStore.Behaviour, as: SessionStoreBehaviour
    @behaviour SessionStoreBehaviour
    alias Charon.{Internal}
    alias Charon.SessionStore.RedisStore.{RedisClient, LuaFunctions}
    import Charon.SessionStore.RedisStore.Config, only: [get_mod_config: 1]
    import Internal.Crypto
    require Logger

    # Implementation goals:
    #  - single round-trip implementations of all callbacks
    #  - no cleanup/0 or equivalent required (all keys eventually expire)
    #  - optimistic locking support (when get-then-updating a session)
    #  - defense-in-depth against a compromised redis server by signing serialized session binaries

    # In order to achieve these goals, a storage format based on three sets is used:
    #  - session_set maps session ids to the actual sessions
    #  - exp_oset (expiration ordered-set) stores refresh exp values mapped to session ids, sorted by exp
    #  - lock_set maps session ids to the lock_version value of the stored session

    # Additionally, a minor performance optimalisation has been added to only prune expired sessions from the
    # sets once on hour, using an expiring redis key called prune_lock.

    @multi ~W(MULTI)
    @exec ~W(EXEC)

    @impl SessionStoreBehaviour
    def get(session_id, user_id, type, config) do
      mod_conf = get_mod_config(config)
      session_set_key = key_data(user_id, type, mod_conf) |> session_set_key()
      signing_key = get_signing_key(mod_conf, config)

      ["HGET", session_set_key, session_id]
      |> RedisClient.command(true)
      |> case do
        {:ok, nil_or_binary} ->
          nil_or_binary
          |> verify(signing_key)
          |> maybe_deserialize()
          |> validate(session_id, user_id, type, Internal.now())

        error ->
          error
      end
    end

    @impl SessionStoreBehaviour
    def upsert(
          session = %{
            id: sid,
            lock_version: lock_version,
            refresh_expires_at: exp,
            refreshed_at: now,
            type: type,
            user_id: uid
          },
          config
        )
        when exp >= now do
      mod_conf = get_mod_config(config)
      key_data = key_data(uid, type, mod_conf)
      session_set_key = session_set_key(key_data)
      exp_oset_key = exp_oset_key(key_data)
      lock_set_key = lock_set_key(key_data)
      prune_lock_key = prune_lock_key(key_data)

      new_lock_version = lock_version + 1
      session = %{session | lock_version: new_lock_version}
      serialized_signed = session |> serialize() |> sign_hmac(get_signing_key(mod_conf, config))

      [
        LuaFunctions.opt_lock_upsert_cmd(
          session_set_key,
          exp_oset_key,
          lock_set_key,
          sid,
          new_lock_version,
          serialized_signed,
          exp
        ),
        LuaFunctions.maybe_prune_expired_cmd(
          session_set_key,
          exp_oset_key,
          lock_set_key,
          prune_lock_key,
          now
        )
      ]
      |> RedisClient.pipeline(true)
      |> case do
        {:ok, ["CONFLICT", _]} -> {:error, :conflict}
        {:ok, [[_, _, _, _, _, _], _]} -> :ok
        error -> redis_result_to_error(error)
      end
    end

    def upsert(_, _), do: :ok

    @impl SessionStoreBehaviour
    def delete(session_id, user_id, type, config) do
      mod_conf = get_mod_config(config)
      key_data = key_data(user_id, type, mod_conf)
      session_set_key = session_set_key(key_data)
      lock_set_key = lock_set_key(key_data)
      exp_oset_key = exp_oset_key(key_data)

      [
        @multi,
        ["HDEL", session_set_key, session_id],
        ["HDEL", lock_set_key, session_id],
        ["ZREM", exp_oset_key, session_id],
        LuaFunctions.resolve_set_exps_cmd(session_set_key, exp_oset_key, lock_set_key),
        @exec
      ]
      |> RedisClient.pipeline(true)
      |> case do
        {:ok, [_, _, _, _, _, transaction_res]} when is_list(transaction_res) -> :ok
        error -> redis_result_to_error(error)
      end
    end

    @impl SessionStoreBehaviour
    def get_all(user_id, type, config) do
      mod_conf = get_mod_config(config)
      key_data = key_data(user_id, type, mod_conf)
      session_set_key = session_set_key(key_data)
      signing_key = get_signing_key(mod_conf, config)
      now = Internal.now()

      with {:ok, values} <- RedisClient.command(["HVALS", session_set_key], true) do
        values
        |> Stream.map(fn nil_or_binary ->
          nil_or_binary
          |> verify(signing_key)
          |> maybe_deserialize()
          |> validate(user_id, type, now)
        end)
        |> Enum.reject(&is_nil/1)
      end
    end

    @impl SessionStoreBehaviour
    def delete_all(user_id, type, config) do
      mod_conf = get_mod_config(config)
      key_data = key_data(user_id, type, mod_conf)
      exp_oset_key = exp_oset_key(key_data)
      session_set_key = session_set_key(key_data)
      lock_set_key = lock_set_key(key_data)

      with {:ok, _} <-
             RedisClient.command(["DEL", exp_oset_key, session_set_key, lock_set_key], true) do
        :ok
      else
        error -> redis_result_to_error(error)
      end
    end

    ###########
    # Private #
    ###########

    # create redis key data
    defp key_data(uid, type, mod_conf),
      do: {to_string(uid), Atom.to_string(type), mod_conf.key_prefix}

    defp serialize(session), do: :erlang.term_to_binary(session)

    defp get_signing_key(%{get_signing_key: get_key}, config), do: get_key.(config)

    # verify the prefixed hmac of a binary
    defp verify(nil, _), do: nil
    defp verify(serialized, key), do: verify_hmac(serialized, key)

    # deserialize the result of verify/3, when valid
    defp maybe_deserialize({:ok, verified}), do: :erlang.binary_to_term(verified)
    defp maybe_deserialize(nil), do: nil

    defp maybe_deserialize(_) do
      Logger.warning("Ignored Redis session with invalid signature.")
      nil
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

    # key for the sorted-by-expiration-timestamp set of the user's session keys
    @doc false
    # the expiration ordered set stores sids and expiration timestamps sorted by the timestamp
    def exp_oset_key({uid, type, prefix}), do: to_key(uid, type, prefix, "e")

    @doc false
    # the session set maps sid's to sessions
    def session_set_key({uid, type, prefix}), do: to_key(uid, type, prefix, "se")

    @doc false
    # the lock set maps sid's to session lock_version values
    def lock_set_key({uid, type, prefix}), do: to_key(uid, type, prefix, "l")

    # create a key from a user_id, sessions type, prefix, and separator
    defp to_key(uid, type, prefix, sep), do: [prefix, ?., sep, ?., uid, ?., type]

    # the prune lock makes sure that expired sessions are only pruned once an hour
    defp prune_lock_key({uid, type, prefix}), do: to_key(uid, type, prefix, "pl")

    # transforms an {:ok, _} result into an {:error, _} result
    defp redis_result_to_error({:ok, error}), do: {:error, inspect(error)}
    defp redis_result_to_error(error), do: error
  end
end
