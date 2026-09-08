class SshChannelState
  let local_id: U32
  var remote_id: U32
  var local_window: U32
  var remote_window: U32
  // Always within SshChannelLimits' bounds: clamped here at construction and on
  // every later assignment. SshSession._channel_send_segmented divides outbound
  // data by this value, so a zero would not terminate and a one would frame one
  // SSH packet — 36 bytes and an AEAD operation — per byte of output.
  var max_packet_size: U32
  let channel_type: String val
  var open: Bool = true
  // Cleared until the open has actually been authorized: by the consumer, for a
  // channel the peer asked us to open, or by the peer's CHANNEL_OPEN_CONFIRMATION
  // for one we opened. The consumer's decision arrives asynchronously while
  // inbound packets keep being dispatched synchronously, so channel state exists
  // before it is authorized and messages naming it must be refused until then.
  var authorized: Bool = false
  var pty: (SshPtyState val | None) = None
  var pty_pending: Bool = false

  new create(local_id': U32, remote_id': U32,
    local_window': U32, remote_window': U32,
    max_packet_size': U32, channel_type': String val)
  =>
    local_id = local_id'
    remote_id = remote_id'
    local_window = local_window'
    remote_window = remote_window'
    max_packet_size = SshChannelLimits.clamp_max_packet(max_packet_size')
    channel_type = channel_type'
