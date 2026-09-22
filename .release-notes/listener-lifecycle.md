## Server consumers are told whether the listener bound

Servers can now report when an `SshListener` is accepting connections or has failed to bind. Previously, neither outcome reached the server consumer, so a port already in use could leave a server with no failure reported. `SshServerNotify` receives these outcomes through `ssh_listener_started` and `ssh_listener_failed`. Each callback identifies its listener, allowing a consumer shared by several listeners to identify and dispose the right one. Existing servers compile unchanged because both callbacks have defaults.

```pony
actor MyServerNotify is SshServerNotify
  be ssh_listener_started(listener: DisposableActor tag) =>
    _env.out.print("listening")

  be ssh_listener_failed(listener: DisposableActor tag) =>
    _env.out.print("could not bind")
    _env.exitcode(1)
```

Start clients only after `ssh_listener_started`: a connect issued straight after constructing the listener can be refused before the bind completes.
