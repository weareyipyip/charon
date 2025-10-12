#!lua name=charon_redis_store_0.0.0+development

------------
-- PUBLIC --
------------

local function opt_lock_upsert(keys, args)
  local session_set_key = unpack(keys)
  local sid, lock_key, lock_version, session, expires_at = unpack(args)

  local current_lock = redis.call("HGET", session_set_key, lock_key)

  -- if current_lock exists, this is an update, not an insert
  if current_lock and current_lock + 1 ~= tonumber(lock_version) then
    return "CONFLICT"
  else
    return redis.call("HSETEX", session_set_key, "EXAT", expires_at, "FIELDS", 2, sid, session, lock_key, lock_version)
  end
end
redis.register_function('opt_lock_upsert_0.0.0+development', opt_lock_upsert)
