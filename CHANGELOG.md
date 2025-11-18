# Changelog

## 4.x

### Breaking

- `Charon.SessionStore.RedisStore`

  - Requires Redis >= 8.0.0 or Valkey >= 9.0.0 or another Redis-compatible key-value store with support for [HSETEX](https://redis.io/docs/latest/commands/hsetex/) and related Redis 8 commands.
  - Simplified implementation that relies on expiring hash fields. This means a single datastructure (instead of 3) now holds a user's sessions, and only a single Redis function is needed instead of several.
  - Added `Charon.SessionStore.RedisStore.Migrate.migrate_v3_to_v4!/1` to facilitate the upgrade. The function should be called during a maintenance window to avoid losing sessions.

- `Charon.TokenFactory.Jwt` dropped support for Blake3 (keyed hashing) signed JWTs, because the Elixir Blake3 lib is unmaintained. The factory now only support OTP `m::crypto`-backed algorithms.

- Config option `:enforce_browser_cookies` has been flipped to true, as a secure default. This can cause problems if you have browser clients that use `:bearer` token transport (which they shouldn't).

- `Charon.Utils.KeyGenerator` no longer caches keys in `m::persistent_term`. A simple cache helper has been added as `Charon.Utils.PersistentTermCache`. While caching of derived keys is often desirable, caching using `m::persistent_term` is not always appropriate; this should not be used for dynamically generated keys, for example, but only for create-once-use-often keys. Calling code should decide this for itself.

- 3.x marked-deprecated functions have been removed:

  - `Charon.Utils.get_token_signature_transport/1`
  - `Charon.Utils.set_token_signature_transport/2`
  - `Charon.Utils.set_user_id/2`
  - `Charon.TokenPlugs.get_token_sig_from_cookie/2`

### Non-breaking

- `Charon.SessionPlugs` / `Charon.Config`

  - Config option `:gen_id` now allows overriding the session / access token / refresh token ID generator. The default remains the same - a 128-bits random url64-encoded string. Generated IDs _must_ be unique and must be a binary.

- `Charon.TokenPlugs` / `Charon.SessionPlugs`

  - Instead of splitting tokens as "header.payload." and "signature", the split has changed to "header.payload" and ".signature", which allows pattern matching on the cookie binary. The old style is still supported for backwards compatibility.

## 3.4.1

- Fix a Blake3-related compiler warning.

## 3.4.0

- Support generating Poly1305 nonces using a configurable function, with `Charon.TokenFactory.Jwt` config option `:gen_poly1305_nonce`. Generated nonces _must_ be unique.

## 3.3.0

- Require Elixir 1.14
- Support Poly1305-signed JWTs by passing a key with type `:poly1305` to `Charon.TokenFactory.Jwt`.
- Default to `JSON` instead of `Jason` on Elixir >= 1.18

## 3.2.0

- Drop `FastGlobal` dependency in favor of OTP's `m::persistent_term` for caching derived keys.

## 3.1.0

- Supports cookie-only tokens (access / refresh tokens fully added to cookies) using `Charon.SessionPlugs.upsert_session/3` opt `:token_transport`.
- Support config option `:enforce_browser_cookies` to force browser clients to not use bearer tokens without any cookies. Browsers are detected by the presence of header "sec-fetch-mode", which is set by all major browsers on every request.
- Improve test support.

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
