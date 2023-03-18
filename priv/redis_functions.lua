#!lua name=charon_redis_store

-------------
-- PRIVATE --
-------------

local function map(enumerable, func)
  local results = {}
  for i=1, #enumerable do
    results[i] = func(enumerable[i])
  end
  return results
end

local function expire_all(keys, at)
  return map(keys, function (v) return redis.call("EXPIREAT", v, at) end)
end

-- remove sids of expired sessions from all sets
local function prune_expired(session_set_key, exp_oset_key, lock_set_key, now)
  local expired = redis.call("ZRANGE", exp_oset_key, "-inf", "("..now, "BYSCORE")

  if #expired == 0 then
    return {0, 0, 0}
  else
    return {
      redis.call("HDEL", session_set_key, unpack(expired)),
      redis.call("ZREM", exp_oset_key, unpack(expired)),
      redis.call("HDEL", lock_set_key, unpack(expired))
    }
  end
end

-- stupid EXPIREAT GT does not work if the key doesn't exist :|
local function incr_exp(key, new_max)
  local current_exp = redis.call("EXPIRETIME", key)
  -- the key does not exist if current_exp == -2
  if current_exp ~= -2 and new_max > current_exp then
    return redis.call("EXPIREAT", key, new_max)
  else
    return 0
  end
end

local function incr_exps(keys, new_max)
  return map(keys, function (v) return incr_exp(v, new_max) end)
end

------------
-- PUBLIC --
------------

-- grab max exp from expiration set and update all relevant set expiration values to it
local function resolve_set_exps(keys, args)
  local session_set_key, exp_oset_key, lock_set_key = unpack(keys)

  local _, score = unpack(redis.call("ZRANGE", exp_oset_key, "+inf", "-inf", "REV", "BYSCORE", "LIMIT", "0", "1", "WITHSCORES"))

  if score then
    return expire_all({session_set_key, exp_oset_key, lock_set_key}, score)
  else
    return {0, 0, 0}
  end
end

-- upsert a session if its lock_version is not stale
-- the function expects to be called with an *increased* lock version
local function opt_lock_upsert(keys, args)
  local session_set_key, exp_oset_key, lock_set_key = unpack(keys)
  local sid, lock_version, session, expires_at = unpack(args)

  local current_lock = redis.call("HGET", lock_set_key, sid)

  -- if current_lock exists, this is an update, not an insert
  if current_lock and current_lock + 1 ~= tonumber(lock_version) then
    return "CONFLICT"
  else
    return {
      redis.call("HSET", session_set_key, sid, session),
      redis.call("ZADD", exp_oset_key, expires_at, sid),
      redis.call("HSET", lock_set_key, sid, lock_version),
      unpack(incr_exps({session_set_key, exp_oset_key, lock_set_key}, tonumber(expires_at)))
    }
  end
end

-- prune_expired wrapped in a once-per-hour-mechanism based on a locking key
local function maybe_prune_expired(keys, args)
  local session_set_key, exp_oset_key, lock_set_key, prune_lock_key = unpack(keys)

  if redis.call("SET", prune_lock_key, "1", "NX", "GET", "EX", 3600) then
    return "SKIPPED"
  else
    local now = unpack(args)
    return prune_expired(session_set_key, exp_oset_key, lock_set_key, now)
  end
end

redis.register_function('charon_resolve_set_exps', resolve_set_exps)
redis.register_function('charon_opt_lock_upsert', opt_lock_upsert)
redis.register_function('charon_maybe_prune_expired', maybe_prune_expired)
