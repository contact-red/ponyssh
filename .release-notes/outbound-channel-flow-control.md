## Stop losing outbound channel data when the peer's window fills

`SshSession.channel_send` sent as much of a buffer as the peer's flow-control window allowed, dropped the rest, and reported `SshWindowExhausted` through `ssh_channel_error`. That error carried no byte count, so a consumer could not tell how much had gone out or where to resume, and `ssh_channel_error` does nothing unless overridden. A server writing more output to a channel than the peer's window allowed lost the tail of it without a trace.

Data offered past the window is now held and sent as the peer grants more window. A buffer is accepted whole or not at all: when the queue is full `channel_send` sends none of that buffer and reports `SshWindowExhausted`, so a consumer is never left working out which part of its buffer went out. The queue holds up to 256 KiB per channel.

A channel carries a byte stream, so one `channel_send` is not one packet: a buffer may be split across several, and one packet may carry the end of one buffer and the start of the next. Frame your own messages if the peer needs to see boundaries.

`SshClientNotify` and `SshServerNotify` gained `ssh_channel_writeable`, called when a channel whose queue filled has drained empty. It is called only for a channel whose `channel_send` was refused, so a consumer that never overflows never sees it. Both interfaces supply a default that does nothing, so existing implementations still compile.

```pony
be ssh_channel_error(session: SshSession tag, channel_id: U32,
  err: SshChannelError val)
=>
  match err
  | SshWindowExhausted => _blocked = true  // none of that buffer was sent
  end

be ssh_channel_writeable(session: SshSession tag, channel_id: U32) =>
  if _blocked then
    _blocked = false
    session.channel_send(channel_id, _retry_buffer)
  end
```

Closing a channel that still has data queued now reports `SshChannelClosed` for the part that was never sent, instead of discarding it silently.
