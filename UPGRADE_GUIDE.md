# Upgrade guide

## 2.x to 3.x

### RedisStore changes

If you use `Charon.SessionStore.RedisStore` you must do the following before upgrading to 3.x:

1.  Upgrade your Redis instance to 7.x.x
1.  Run `Charon.SessionStore.RedisStore.migrate_sessions/1`
1.  If you explicitly set config option `:allow_unsigned?`, you must remove your override. Support for this config option has been dropped.

### Deprecated functions

All marked-as-deprecated functions have been dropped, so make sure your code does not use these functions anymore. The compiler emits warnings if you do.
