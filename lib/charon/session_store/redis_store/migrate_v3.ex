defmodule Charon.SessionStore.RedisStore.MigrateV3 do
  @moduledoc """
  Migrate Redis data from the v3 data format to the v4 data format.
  """
  alias Charon.SessionStore.RedisStore
  alias RedisStore.{RedisClient, StoreImpl}
  import RedisStore.Config

  @doc """
  Migrate Redis data from the v3 data format to the v4 data format.
  This is a (relatively) slow operation that iterates keys in the instance and does not guarantee atomicity.
  This function should be executed during a maintenance window.
  """
  @spec migrate_v3_to_v4(Charon.Config.t()) :: :ok
  def migrate_v3_to_v4(config) do
    mod_conf = get_mod_config(config)
    prefix = mod_conf.key_prefix
    signing_key = StoreImpl.get_signing_key(mod_conf, config)

    # the v3 key format is prefix.separator.uid.type (the separator distinguishes between the session/lock/exp sets)
    # the session set separator is "se"
    {:ok, session_set_keys} = RedisClient.command(["KEYS", "#{prefix}.se.*"])

    Enum.each(session_set_keys, fn session_set_key ->
      {:ok, sessions} = RedisClient.command(["HVALS", session_set_key])

      sessions
      |> Stream.map(fn serialized ->
        serialized |> StoreImpl.verify_signature(signing_key) |> StoreImpl.maybe_deserialize()
      end)
      |> Enum.each(&(:ok = StoreImpl.upsert(&1, config)))

      [_prefix, _sep, uid, type] = String.split(session_set_key, ".")
      exp_oset_key = "#{prefix}.e.#{uid}.#{type}"
      lock_set_key = "#{prefix}.l.#{uid}.#{type}"
      {:ok, _} = RedisClient.command(["DEL", session_set_key, exp_oset_key, lock_set_key])
    end)
  end
end
