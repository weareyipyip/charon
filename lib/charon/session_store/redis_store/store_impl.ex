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
    #
    # In order to achieve these goals, we store sessions in a hashset with expiring subkeys:
    #   sid -> session
    #   l.sid -> lock version
    #
    # We check the lock and update the session+lock atomically using a Redis function.

    @lock_key_prefix "l."

    @impl SessionStoreBehaviour
    def get(session_id, user_id, type, config) do
      mod_conf = get_mod_config(config)
      session_set_key = session_set_key(user_id, type, mod_conf)
      signing_key = get_signing_key(mod_conf, config)

      ["HGET", session_set_key, session_id]
      |> RedisClient.command(true)
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
      mod_conf = get_mod_config(config)
      session_set_key = session_set_key(session.user_id, session.type, mod_conf)
      lock_key = lock_key(sid)
      signing_key = get_signing_key(mod_conf, config)

      new_lock = lock + 1
      session = %{session | lock_version: new_lock}
      signed = session |> serialize() |> sign_hmac(signing_key)

      LuaFunctions.opt_lock_upsert_cmd(session_set_key, sid, lock_key, new_lock, signed, exp)
      |> RedisClient.command(true)
      |> case do
        {:ok, "CONFLICT"} -> {:error, :conflict}
        {:ok, 1} -> :ok
        error -> redis_result_to_error(error)
      end
    end

    def upsert(_, _), do: :ok

    @impl SessionStoreBehaviour
    def delete(session_id, user_id, type, config) do
      mod_conf = get_mod_config(config)
      session_set_key = session_set_key(user_id, type, mod_conf)
      lock_key = lock_key(session_id)

      ["HDEL", session_set_key, session_id, lock_key]
      |> RedisClient.command(true)
      |> case do
        {:ok, _} -> :ok
        error -> redis_result_to_error(error)
      end
    end

    @impl SessionStoreBehaviour
    def get_all(user_id, type, config) do
      mod_conf = get_mod_config(config)
      session_set_key = session_set_key(user_id, type, mod_conf)
      signing_key = get_signing_key(mod_conf, config)
      now = Internal.now()

      with {:ok, values} <- RedisClient.command(["HGETALL", session_set_key], true) do
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
      mod_conf = get_mod_config(config)
      session_set_key = session_set_key(user_id, type, mod_conf)

      with {:ok, _} <- RedisClient.command(["DEL", session_set_key], true) do
        :ok
      else
        error -> redis_result_to_error(error)
      end
    end

    ###########
    # Private #
    ###########

    defp serialize(session), do: :erlang.term_to_binary(session)

    defp get_signing_key(%{get_signing_key: get_key}, config), do: get_key.(config)

    # verify the prefixed hmac of a binary
    defp verify_signature(nil, _), do: nil
    defp verify_signature(serialized, key), do: verify_hmac(serialized, key)

    # deserialize the result of verify/3, when valid
    defp maybe_deserialize({:ok, verified}), do: :erlang.binary_to_term(verified)
    defp maybe_deserialize(nil), do: nil

    defp maybe_deserialize(_) do
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
end
