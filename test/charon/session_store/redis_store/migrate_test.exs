defmodule Charon.SessionStore.RedisStore.MigrateTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias Charon.SessionStore.RedisStore.Migrate
  alias Charon.SessionStore.RedisStore
  import Charon.{TestUtils, Internal}
  import Charon.Internal.Crypto
  alias RedisStore.{RedisClient}
  require Logger

  @ttl 100
  @now now()
  @exp @now + @ttl
  @mod_conf %{} |> RedisStore.init_config()
  @config %{
    TestApp.Charon.get()
    | session_ttl: :infinite,
      refresh_token_ttl: @ttl,
      optional_modules: %{RedisStore => @mod_conf}
  }
  @sid "a"
  @uid 426
  @user_session test_session(
                  id: @sid,
                  user_id: @uid,
                  refresh_expires_at: @exp,
                  refreshed_at: @now
                )

  setup_all do
    redix_opts = [host: System.get_env("REDIS_HOSTNAME", "localhost")]
    start_supervised!({RedisStore, redix_opts: redix_opts})
    :ok
  end

  setup do
    RedisClient.command(~w(FLUSHDB))
    :ok
  end

  defp serialize(session), do: session |> :erlang.term_to_binary()
  defp sign(binary), do: sign_hmac(binary, RedisStore.default_signing_key(@config))
  defp to_result({:ok, result}), do: result

  defp add_to_oset(set_k, score, v),
    do: 1 = RedisClient.command(["ZADD", set_k, score, v]) |> to_result()

  defp add_to_hash_set(set_k, k, v),
    do: 1 = RedisClient.command(["HSET", set_k, k, v]) |> to_result()

  # the expiration ordered set stores sids and expiration timestamps sorted by the timestamp
  defp exp_oset_key(uid, type), do: to_key(uid, type, @mod_conf.key_prefix, "e")

  # the session set maps sid's to sessions
  defp old_session_set_key(uid, type), do: to_key(uid, type, @mod_conf.key_prefix, "se")

  # the lock set maps sid's to session lock_version values
  defp lock_set_key(uid, type), do: to_key(uid, type, @mod_conf.key_prefix, "l")

  # create a key from a user_id, sessions type, prefix, and separator
  defp to_key(uid, type, prefix, sep), do: "#{prefix}.#{sep}.#{uid}.#{type}"

  defp insert_cmd(session = %{id: sid, user_id: uid, type: type}) do
    serialized_signed = session |> serialize() |> sign()

    [
      ["ZADD", exp_oset_key(uid, type), session.refresh_expires_at, sid],
      ["HSET", lock_set_key(uid, type), sid, session.lock_version],
      ["HSET", old_session_set_key(uid, type), sid, serialized_signed]
    ]
  end

  defp insert(session_or_sessions) do
    session_or_sessions |> List.wrap() |> Enum.flat_map(&insert_cmd/1) |> RedisClient.pipeline()
  end

  describe "migrate/1" do
    setup do
      u1_s1 = @user_session
      u1_s2 = %{u1_s1 | id: "b", refresh_expires_at: @exp + 10, lock_version: 200}
      # expired
      u1_s3 = %{u1_s1 | id: "c", refresh_expires_at: @now}
      u2_s1 = %{@user_session | id: "d", user_id: @uid + 1, lock_version: 300}
      u2_s2 = %{u2_s1 | id: "e", refresh_expires_at: @exp + 20, lock_version: 400}

      Enum.map([u1_s1, u1_s2, u1_s3, u2_s1, u2_s2], &insert/1)

      [
        u1_key: session_set_key(@uid, @user_session.type),
        u2_key: session_set_key(@uid + 1, @user_session.type)
      ]
    end

    test "all non-expired sessions are migrated", seeds do
      assert %{count: 5, failed: 0} = Migrate.migrate_v3_to_v4!(@config)

      {:ok, keys} = RedisClient.command(["HKEYS", seeds.u1_key])
      assert ["a", "b", "l.a", "l.b"] == Enum.sort(keys)

      {:ok, keys} = RedisClient.command(["HKEYS", seeds.u2_key])
      assert ["d", "e", "l.d", "l.e"] == Enum.sort(keys)

      # all old sets are removed
      {:ok, [_, _]} = RedisClient.command(["KEYS", "*"])
    end

    test "exp values are set", seeds do
      assert %{count: 5, failed: 0} = Migrate.migrate_v3_to_v4!(@config)

      {:ok, exps} = RedisClient.command(["HEXPIRETIME", seeds.u1_key, "FIELDS", "2", "a", "b"])
      assert [@exp, @exp + 10] == exps

      {:ok, exps} = RedisClient.command(["HEXPIRETIME", seeds.u2_key, "FIELDS", "2", "d", "e"])
      assert [@exp, @exp + 20] == exps
    end

    test "locks are set", seeds do
      assert %{count: 5, failed: 0} = Migrate.migrate_v3_to_v4!(@config)

      {:ok, ~w(0 200)} = RedisClient.command(["HMGET", seeds.u1_key, "l.a", "l.b"])
      {:ok, ~w(300 400)} = RedisClient.command(["HMGET", seeds.u2_key, "l.d", "l.e"])
    end

    test "all old datastructures are deleted" do
      assert %{count: 5, failed: 0} = Migrate.migrate_v3_to_v4!(@config)
      {:ok, keys} = RedisClient.command(~w(KEYS *))
      assert ["charon_.426.full", "charon_.427.full"] == Enum.sort(keys)
    end

    test "is idempotent", seeds do
      assert %{count: 5, failed: 0} = Migrate.migrate_v3_to_v4!(@config)
      assert %{count: 0, failed: 0} = Migrate.migrate_v3_to_v4!(@config)

      {:ok, keys} = RedisClient.command(["HKEYS", seeds.u1_key])
      assert ["a", "b", "l.a", "l.b"] == Enum.sort(keys)

      {:ok, keys} = RedisClient.command(["HKEYS", seeds.u2_key])
      assert ["d", "e", "l.d", "l.e"] == Enum.sort(keys)
    end

    test "handles invalid sessions gracefully", seeds do
      u2_s3 = %{@user_session | user_id: @uid + 1, id: "f"}
      signed = u2_s3 |> :erlang.term_to_binary() |> sign_hmac("boom")
      add_to_hash_set(old_session_set_key(u2_s3.user_id, u2_s3.type), "f", signed)
      add_to_hash_set(lock_set_key(u2_s3.user_id, u2_s3.type), "f", 1)
      add_to_oset(exp_oset_key(u2_s3.user_id, u2_s3.type), @exp, "f")

      assert capture_log(fn ->
               assert %{count: 6, failed: 1} = Migrate.migrate_v3_to_v4!(@config)
             end) =~ "Ignored Redis session"

      {:ok, keys} = RedisClient.command(["HKEYS", seeds.u2_key])
      assert ["d", "e", "l.d", "l.e"] == Enum.sort(keys)

      # invalid sessions are left in place
      {:ok, [_, _, _, _, _]} = RedisClient.command(["KEYS", "*"])
    end
  end

  describe "migrate/1 bulk" do
    test "works with many users and sessions" do
      uids = 5000
      sids_per_user = 5
      session_n = uids * sids_per_user

      for uid <- 1..uids,
          sid <- 1..sids_per_user do
        sid = uid * uids + sid
        %{@user_session | user_id: "#{uid}", id: "#{sid}"}
      end
      |> Stream.chunk_every(1000)
      |> Enum.each(&insert/1)

      start = System.monotonic_time(:millisecond)

      assert %{count: session_n, failed: 0} == Migrate.migrate_v3_to_v4!(@config)

      stop = System.monotonic_time(:millisecond)
      Logger.debug("Migrated #{session_n} sessions in #{stop - start}ms")

      {:ok, keys} = RedisClient.command(~w(KEYS *))
      assert Enum.count(keys) == uids
    end
  end
end
