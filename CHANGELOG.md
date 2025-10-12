# Changelog

## 4.x

### Breaking

- `Charon.TokenFactory.Jwt`

  - Dropped support for Blake3 (keyed hashing) signed JWTs, because the Elixir Blake3 lib is unmaintained. The factory now only support OTP `:crypto`-backed algorithms.

- `Charon.SessionStore.RedisStore`

  - Requires Redis >= 8.0.0 or Valkey >= 9.0.0 or another Redis-API-compatible key-value store with support for [HSETEX](https://redis.io/docs/latest/commands/hsetex/) and related Redis 8 commands.
  - Simplified implementation that relies on expiring hash fields. This means a single datastructure (instead of 3) now holds a user's sessions, and only a single Redis function is needed instead of several.

- 3.x marked-deprecated functions have been removed:

  - `Charon.Utils.get_token_signature_transport/1`
  - `Charon.Utils.set_token_signature_transport/2`
  - `Charon.Utils.set_user_id/2`
  - `Charon.TokenPlugs.get_token_sig_from_cookie/2`

## 3.x

### Breaking

- `Charon.SessionStore.RedisStore`

  - requires Redis >= 7.x.x
  - uses a Redix connection pool by itself, which requires initialization under the application supervision tree
  - implements optimistic locking
  - uses a new storage format based on hash sets, to which sessions are migrated starting from Charon 2.8
  - uses Redis functions to implement all session store operations in a single round trip to the Redis instance
  - support for unsigned binaries has been dropped
    - config options `:allow_unsigned?` has been removed
    - `migrate_sessions/1` has been removed
    - sessions that have not been migrated using `migrate_sessions/1` can no longer be used

- `Charon.SessionStore.LocalStore`

  - implements optimistic locking

- 2.x marked-deprecated functions have been removed:

  - `Charon.Models.Session.deserialize/2`
  - `Charon.Models.Session.serialize/1`
  - `Charon.SessionStore.delete/3`
  - `Charon.SessionStore.get/3`
  - `Charon.SessionStore.delete_all/2`
  - `Charon.SessionStore.get_all/2`
  - `Charon.SessionStore.RedisStore.cleanup/1`
  - `Charon.TokenPlugs.verify_refresh_token_fresh/2`

- `Charon.TokenPlugs.verify_token_signature/2` no longer adds default value "full" for claim "styp".
  This should not result in issues for tokens created by Charon 2.x.x deployments.
  Older deployments may wish to add a plug after `Charon.TokenPlugs.verify_token_signature/2` that adds this default claim.
