# ponyssh

A production-grade SSH-2 client/server library for Pony.

## Status

ponyssh is alpha-level software that will change frequently. Expect breaking changes. That said, you should feel comfortable experimenting with it in your projects.

## Installation

* Install [corral](https://github.com/ponylang/corral)
* `corral add github.com/contact-red/ponyssh.git --version 0.1.0`
* `corral fetch` to fetch your dependencies
* `use "ssh_server"` (and/or `use "ssh_client"`) to include the package you need:
  * `use "ssh_client"` — create outbound client sessions
  * `use "ssh_server"` — accept inbound connections
  * `use "ssh_transport"` — session, notify interfaces, algorithm preferences
  * `use "ssh_connection"` — channel multiplexing and PTY support
  * `use "ssh_auth"` — authentication message types
  * `use "ssh_crypto"` — cipher, MAC, and key primitives
  * `use "ssh_error"` — error union types
* `corral run -- ponyc -D openssl_3.0.x` to compile your application

## Dependencies

ponyssh links against OpenSSL 3.0.x at compile time and selects the backend with the `openssl_3.0.x` compile-time define. You need the OpenSSL development files installed in your build environment.

### Installing on APT based Linux distributions

```bash
sudo apt-get install -y libssl-dev
```

### Installing on RPM based Linux distributions

```bash
sudo dnf install openssl-devel
```

### Installing on macOS with Homebrew

```bash
brew update
brew install openssl@3
```

## Usage

A minimal echo server. See [`examples/echo-server`](examples/echo-server) for the complete, runnable version.

```pony
use "net"
use "ssh_transport"
use "ssh_error"
use "ssh_server"

actor Main
  new create(env: Env) =>
    let pem: Array[U8] val = MyHostKey()  // your host key, PEM-encoded

    // Algorithm preferences default to the implemented set; to customise them
    // pass `SshAlgorithmPreferences` with named arguments and override only the
    // categories you need.
    let config =
      match MakeSshServerConfig(pem, "0.0.0.0", "2222")
      | let ready: SshServerConfig val => ready
      | SshServerHostKeyLoadFailed =>
        env.err.print("server host key could not be loaded")
        env.exitcode(1)
        return
      | let err: SshServerChannelWindowTooSmall =>
        env.err.print(err.string())
        env.exitcode(1)
        return
      end

    let auth = TCPListenAuth(env.root)
    SshListener(auth, config, MyServerNotify(env))
```

Your `MyServerNotify` implements `SshServerNotify`. The listener reports its bind outcome to it through `ssh_listener_started` and `ssh_listener_failed`; a client started before `ssh_listener_started` can be refused. Authentication and authorization **deny by default**: implement `validate_password` / `validate_publickey` to accept credentials, and override the channel/shell callbacks to grant access (they reject unless overridden).

`MakeSshServerConfig` rejects host key PEM that cannot be loaded and channel receive windows below 256 bytes. The default window is 2 MiB per channel. Set `channel_window'` when calling `MakeSshServerConfig` to use another value.

A minimal client:

```pony
use "net"
use "ssh_transport"
use "ssh_auth"
use "ssh_client"

actor Main
  new create(env: Env) =>
    let config = SshClientConfig("example.com", "22", "alice",
      recover val [as SshAuthMethod val: SshPasswordAuth("hunter2")] end)
    let auth = TCPConnectAuth(env.root)
    SshConnector.connect(auth, config, MyClientNotify(env))
```

`MyClientNotify` implements `SshClientNotify`. It must approve the server host key in `ssh_verify_host_key` (call `session.accept_host_key()` or `session.reject_host_key()`) and acts on the session once `ssh_ready` fires.

When a client sends `channel_request_shell` or `channel_request_exec` with `want_reply = true`, `ssh_channel_request_result` reports the channel ID and whether the peer accepted the request. SSH replies do not identify the request. Wait for a result before sending another reply-seeking request on the same channel if you need to associate the result with a request.

`channel_send` accepts at most 32768 bytes per call. Every call produces `ssh_channel_send_result` with the original array, the number of bytes admitted locally, and a `SshSendOutcome`. `SshSendComplete` means the full array was admitted to the TCP bridge or the bounded rekey queue; it does not confirm delivery to the peer. If the result is `SshSendWindowBlocked`, retain `data.trim(accepted)` and retry it after `ssh_channel_window_available`. A window hint does not reserve credit, so a retry may block again. Clear retained data when the channel or session closes.

Both `SshClientNotify` and `SshServerNotify` implementations must provide the result and window callbacks. The [echo server](examples/echo-server/main.pony) retains a blocked suffix and retries it after a hint.

## API Documentation

[https://ponyssh.contact.red/](https://ponyssh.contact.red/)
