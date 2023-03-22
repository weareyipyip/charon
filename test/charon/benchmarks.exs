Logger.configure(level: :info)

alias Charon.{Internal, SessionStore, Models}
alias Charon.Config, as: CharonConfig
alias Models.{Session}
alias SessionStore.{RedisStore}
alias RedisStore.RedisClient
alias Internal.{Crypto}

RedisStore.start_link()

charon_config =
  CharonConfig.from_enum(token_issuer: "local", get_base_secret: fn -> "very secure string" end)

flushdb = fn -> RedisClient.command(~w(FLUSHDB)) end

now = Internal.now()
ttl = 1000
exp = now + ttl

generate_session = fn uid, sid ->
  %Session{
    id: sid,
    user_id: uid,
    created_at: now,
    expires_at: exp,
    refresh_expires_at: exp,
    refresh_token_id: Crypto.random_url_encoded(16),
    tokens_fresh_from: 0,
    refreshed_at: now
  }
end

generate_sessions = fn ->
  for u <- 1..1000 do
    for _s <- 1..10 do
      sid = Crypto.random_url_encoded(16)
      :ok = generate_session.(u, sid) |> RedisStore.upsert(charon_config)
      {u, sid}
    end
  end
  |> List.flatten()
  |> Enum.shuffle()
end

Benchee.run(%{
  "get" => {
    fn {uid, sid} -> RedisStore.get(sid, uid, :full, charon_config) end,
    before_each: &Enum.random/1,
    before_scenario: fn _ ->
      flushdb.()
      generate_sessions.()
    end
  },
  "get_all" => {
    fn uid -> RedisStore.get_all(uid, :full, charon_config) end,
    before_each: &Enum.random/1,
    before_scenario: fn _ ->
      flushdb.()
      generate_sessions.()
      1..1000
    end
  },
  "delete" => {
    fn {uid, sid} -> RedisStore.delete(sid, uid, :full, charon_config) end,
    before_each: &Enum.random/1,
    before_scenario: fn _ ->
      flushdb.()
      generate_sessions.()
    end
  },
  "upsert" => {
    fn uid ->
      generate_session.(uid, Crypto.random_url_encoded(16)) |> RedisStore.upsert(charon_config)
    end,
    before_each: &Enum.random/1,
    before_scenario: fn _ ->
      flushdb.()
      1..1000
    end
  }
})
