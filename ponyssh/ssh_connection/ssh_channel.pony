class SshChannelState
  let local_id: U32
  var remote_id: U32
  var local_window: U32
  var remote_window: U32
  var max_packet_size: U32
  let channel_type: String val
  var open: Bool = true
  var pty: (SshPtyState val | None) = None

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
