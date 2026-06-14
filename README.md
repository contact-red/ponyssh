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
use "lori"
use "ssh_transport"
use "ssh_server"

actor Main
  new create(env: Env) =>
    let pem: Array[U8] val = // your host key, PEM-encoded
    let ciphers = recover val
      let a = Array[String val]
      a.push("aes256-gcm@openssh.com")
      a
    end
    let prefs = SshAlgorithmPreferences(
      recover val let a = Array[String val]; a.push("curve25519-sha256"); a end,
      recover val let a = Array[String val]; a.push("ssh-ed25519"); a end,
      ciphers, ciphers,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end)
    let config = SshServerConfig(pem, "0.0.0.0", "2222", prefs)
    let auth = TCPListenAuth(env.root)
    SshListener(auth, config, MyServerNotify(env))
```

Your `MyServerNotify` implements `SshServerNotify` to validate credentials and handle channel events.

## API Documentation

[https://ponyssh.contact.red/](https://ponyssh.contact.red/)
