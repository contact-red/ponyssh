use "collections"
use "../ssh_error"

class SshChannelManager
  var _next_local_id: U32 = 0
  let _channels: Map[U32, SshChannelState] = Map[U32, SshChannelState]

  fun ref open_channel(channel_type: String val): U32 =>
    """Allocate local channel ID and create pending state."""
    let id = _next_local_id
    _next_local_id = _next_local_id + 1
    let initial_window: U32 = 0x200000  // 2MB
    _channels(id) = SshChannelState(id, 0, initial_window, 0, 0, channel_type)
    id

  fun ref confirm_channel(local_id: U32, remote_id: U32,
    remote_window: U32, max_packet_size: U32): (None | SshChannelError)
  =>
    """Confirm a pending channel open."""
    try
      let ch = _channels(local_id)?
      ch.remote_id = remote_id
      ch.remote_window = remote_window
      ch.max_packet_size = max_packet_size
      None
    else
      SshChannelClosed
    end

  fun ref accept_channel(local_id: U32, remote_id: U32,
    remote_window: U32, max_packet_size: U32, channel_type: String val): U32
  =>
    """Accept an incoming channel open from remote (server side)."""
    let id = _next_local_id
    _next_local_id = _next_local_id + 1
    let initial_window: U32 = 0x200000
    _channels(id) = SshChannelState(id, remote_id, initial_window,
      remote_window, max_packet_size, channel_type)
    id

  fun ref channel_data_send(local_id: U32, data_size: USize):
    (U32 | SshChannelError)
  =>
    """Check window allows sending, return remote channel ID. Caller handles framing."""
    try
      let ch = _channels(local_id)?
      if not ch.open then return SshChannelClosed end
      if ch.remote_window < data_size.u32() then return SshWindowExhausted end
      ch.remote_window = ch.remote_window - data_size.u32()
      ch.remote_id
    else
      SshChannelClosed
    end

  fun ref channel_data_received(local_id: U32, data_size: USize) =>
    """Decrease local window after receiving data."""
    try
      let ch = _channels(local_id)?
      let size = data_size.u32().min(ch.local_window)
      ch.local_window = ch.local_window - size
    end

  fun ref window_adjust(local_id: U32, bytes: U32) =>
    """Increase remote window for channel."""
    try
      let ch = _channels(local_id)?
      ch.remote_window = ch.remote_window + bytes
    end

  fun ref local_window_adjust(local_id: U32, bytes: U32) =>
    """Increase local window for channel (used when sending WINDOW_ADJUST to remote)."""
    try
      let ch = _channels(local_id)?
      ch.local_window = ch.local_window + bytes
    end

  fun ref close_channel(local_id: U32) =>
    """Remove channel state."""
    try _channels.remove(local_id)? end

  fun ref find_by_remote_id(remote_id: U32): (U32 | None) =>
    """Find local ID for a remote channel ID."""
    for (local_id, ch) in _channels.pairs() do
      if ch.remote_id == remote_id then return local_id end
    end
    None

  fun ref get(local_id: U32): (SshChannelState ref | None) =>
    try _channels(local_id)? else None end

  fun channel_count(): USize =>
    _channels.size()
