# Upgrade guide

## 2.x to 3.x

### RedisStore changes

If you use `Charon.SessionStore.RedisStore` you must do the following before upgrading to 3.x:

1.  Update Charon to >= 2.8.0
1.  Upgrade your Redis instance to 7.x.x (this can be an in-place upgrade)
1.  Run `Charon.SessionStore.RedisStore.migrate_sessions/1`
1.  If you explicitly set config options `:allow_unsigned?` and `:redix_module`, you must remove your overrides. Support for these config options has been dropped.
1.  Initialize the Redix connection pool in your supervision tree. See readme section [setting up a sessionstore](./README.md#setting-up-a-session-store).
1.  Remove your Redix module (if you don't use it for anything else).

### Deprecated functions

All marked-as-deprecated functions have been dropped, so make sure your code does not use these functions anymore. The compiler emits warnings if you do.
