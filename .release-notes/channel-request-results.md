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
