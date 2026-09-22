## Report server configuration errors

`MakeSshServerConfig` now returns a configuration or an error that identifies whether the host key PEM could not be loaded or the channel receive window is below 256 bytes. Replace calls to the partial `SshServerConfig` constructor with a match on this result.

Before:

```pony
let config = SshServerConfig(pem, "0.0.0.0", "2222")?
```

After:

```pony
let config =
  match MakeSshServerConfig(pem, "0.0.0.0", "2222")
  | let ready: SshServerConfig val => ready
  | let err: SshServerConfigError =>
    env.err.print(err.string())
    return
  end
```
