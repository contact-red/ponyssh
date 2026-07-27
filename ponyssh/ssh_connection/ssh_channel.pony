use "buffered"

class SshChannelState
  let local_id: U32
  var remote_id: U32
  var local_window: U32
  var remote_window: U32
  var max_packet_size: U32
  let channel_type: String val
  var open: Bool = true
  var pty: (SshPtyState val | None) = None
  var pty_pending: Bool = false
  // Outbound data accepted from the consumer that the peer's send window has no
  // room for yet, oldest first, drained as the peer grants window. A Reader
  // holds it: despite the name it is a queue of byte chunks that hands back a
  // bounded prefix and keeps the remainder, which is exactly what draining
  // against a send window needs.
  embed pending_send: Reader = Reader
  // Set when a write was refused because the queue was full, so the session
  // knows to tell the consumer once the queue drains that it may resume.
  var send_blocked: Bool = false

  new create(local_id': U32, remote_id': U32,
    local_window': U32, remote_window': U32,
    max_packet_size': U32, channel_type': String val)
  =>
    local_id = local_id'
    remote_id = remote_id'
    local_window = local_window'
    remote_window = remote_window'
    max_packet_size = max_packet_size'
    channel_type = channel_type'
