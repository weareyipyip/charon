# Upgrade guide

## 3.x to 4.x

### RedisStore changes

If you use `Charon.SessionStore.RedisStore` you must do the following before upgrading to 4.x:

1. Prepare a maintenance window during which no session write operations take place (or risk an in-place data migration, with the possibility of some sessions being lost).
1. Update Charon to 4.x.
1. Upgrade your Redis instance to 8.x.x or Valkey to 9.x.x.
1. Run `Charon.SessionStore.RedisStore.Migrate.migrate_v3_to_v4!/1`.

### JWT changes

JWT's signed with Blake3 keyed hashing are no longer supported because the Elixir Blake3 library is unmaintained. If you use this algorithm to sign your JWTs, you must migrate away from it. This can be done by replacing the key in the keyset, but that means you log out all existing sessions, which may or may not be a problem. However, Charon support cycling your keys gracefully: take a look at `Charon.TokenFactory.Jwt`.

### Browser clients using `:bearer` token transport

Config option `:enforce_browser_cookies` has been flipped to true, as a secure default. This can cause problems if you have browser clients that use `:bearer` token transport (which they shouldn't). Make sure your browser clients request `:cookie` or `:cookie_only` tokens, and protect them against [CSRF](./README.md#csrf-protection).

### Deprecated functions

All marked-as-deprecated functions from v3 have been dropped, so make sure your code does not use these functions anymore. The compiler emits warnings if you do.

## 2.x to 3.x

### RedisStore changes

If you use `Charon.SessionStore.RedisStore` you must do the following before upgrading to 3.x:

1. Update Charon to >= 2.8.0
1. Upgrade your Redis instance to 7.x.x (this can be an in-place upgrade)
1. Run `Charon.SessionStore.RedisStore.migrate_sessions/1`
1. If you explicitly set config options `:allow_unsigned?` and `:redix_module`, you must remove your overrides. Support for these config options has been dropped.
1. Initialize the Redix connection pool in your supervision tree. See readme section [setting up a sessionstore](./README.md#setting-up-a-session-store).
1. Remove your Redix module (if you don't use it for anything else).

### Deprecated functions

All marked-as-deprecated functions have been dropped, so make sure your code does not use these functions anymore. The compiler emits warnings if you do.
