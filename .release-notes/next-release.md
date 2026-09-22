## Use the standard library's `net` package instead of lori

ponyssh's TCP layer now comes from the standard library's `net` package, which is lori brought into ponyc. lori is no longer a dependency, so `corral fetch` no longer downloads it, and `use "lori"` in your own code becomes `use "net"`. The types are unchanged: `TCPListenAuth`, `TCPConnectAuth`, `TCPConnection`, and the lifecycle receivers keep their names.

Before:

```pony
use "lori"
use "ssh_server"
```

After:

```pony
use "net"
use "ssh_server"
```

This requires ponyc 0.72.0 or later, the first release that ships `net`.

## Report channel-send progress so callers can retry after window exhaustion

`channel_send` could transmit only the prefix that fit the peer's window and discard the rest. It now reports the number of bytes admitted locally for every call. When the window blocks a send, retain the unsent suffix and retry it after `ssh_channel_window_available`. Each call is limited to 32768 bytes. Both client and server notify implementations must add `ssh_channel_send_result` and `ssh_channel_window_available` callbacks.

Peer-advertised channel packet limits below 256 bytes are now rejected instead of sending packets larger than that limit. `MakeSshServerConfig` also accepts an optional `channel_window'` value to control the receive window advertised to clients; the default remains 2 MiB, and values below 256 bytes are rejected.

Before:

```pony
be send(session: SshSession tag, channel_id: U32,
  data: Array[U8] val) =>
  session.channel_send(channel_id, data)
```

After, inside a notify actor whose `_output` map is keyed by session identity and holds a `pending` map keyed by channel ID:

```pony
be send(session: SshSession tag, channel_id: U32,
  data: Array[U8] val) =>
  session.channel_send(channel_id, data)

be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
  data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
=>
  match outcome
  | SshSendWindowBlocked =>
    try _output(session)?.pending(channel_id) = data.trim(accepted) end
  else
    try _output(session)?.pending.remove(channel_id)? end
  end

be ssh_channel_window_available(session: SshSession tag, channel_id: U32) =>
  try session.channel_send(channel_id, _output(session)?.pending(channel_id)?) end

be ssh_channel_closed(session: SshSession tag, channel_id: U32) =>
  try _output(session)?.pending.remove(channel_id)? end

be ssh_disconnected(session: SshSession tag) =>
  try _output.remove(session)? end
```

The echo server example shows the complete per-session state and retry logic.

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

## Report channel request replies to clients

Clients can now receive the peer's success or failure reply to a shell or exec channel request through `SshClientNotify.ssh_channel_request_result`. The callback reports the channel ID and whether the request was accepted. Add the callback to each `SshClientNotify` implementation. Requests sent with `want_reply = false` produce no callback.

Before:

```pony
be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
  session.channel_request_exec(channel_id, "whoami")
```

After:

```pony
be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
  session.channel_request_exec(channel_id, "whoami")

be ssh_channel_request_result(session: SshSession tag,
  channel_id: U32, accepted: Bool)
=>
  if not accepted then
    session.channel_close(channel_id)
  end
```

