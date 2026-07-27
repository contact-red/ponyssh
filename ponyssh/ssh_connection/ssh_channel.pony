use "collections"

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
  // room for yet, oldest first, drained as the peer grants window. A list, not
  // an array, because it is consumed from the head. pending_bytes is the total
  // still queued, kept alongside so the queue cap can be checked without
  // walking the list.
  embed pending_send: List[Array[U8] val] = List[Array[U8] val]
  var pending_bytes: USize = 0
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
