# Changelog

## 3.x

### Breaking

- `Charon.SessionStore.RedisStore` now requires Redis >= 7.x.x

- 2.x marked-deprecated functions have been removed:

  - `Charon.Models.Session.deserialize/2`
  - `Charon.Models.Session.serialize/1`
  - `Charon.SessionStore.delete/3`
  - `Charon.SessionStore.get/3`
  - `Charon.SessionStore.delete_all/2`
  - `Charon.SessionStore.get_all/2`
  - `Charon.SessionStore.RedisStore.cleanup/1`
  - `Charon.TokenPlugs.verify_refresh_token_fresh/2`

- `Charon.SessionStore.RedisStore` support for unsigned binaries has been dropped.

  - config options `:allow_unsigned?` has been removed
  - `migrate_sessions/1` has been removed
  - sessions that have not been migrated using `migrate_sessions/1` can no longer be used

- `Charon.SessionStore.RedisStore` now uses a Redix connection pool by itself,
  which requires initialization under the application supervision tree.
