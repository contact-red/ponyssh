## Limit authentication attempts per connection

A server session answered an unlimited number of authentication attempts on one TCP connection. Each rejection sent SSH_MSG_USERAUTH_FAILURE and left the session ready for the next attempt, so a peer could guess passwords at line rate without opening a new connection, and without producing the connection churn that rate limiting outside the process watches for. Consumers had no way to add the limit themselves: `validate_password` and `validate_publickey` carry no session identity, and one `SshServerNotify` is shared across every session a listener creates.

A session now disconnects after six failed attempts, matching OpenSSH's `MaxAuthTries` default.
