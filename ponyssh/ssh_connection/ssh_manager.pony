use "collections"
use "../ssh_error"

primitive SshChannelWindow
  """The default receive window advertised for a channel."""
  fun initial(): U32 => 0x200000  // 2 MiB

primitive SshChannelLimits
  """
  Bounds on channel state, enforced so a hostile peer cannot grow it without
  bound.
  """
  fun max_concurrent(): USize =>
    """
    Maximum number of channels held at once. A peer that repeatedly opens
    channels must not grow stored channel state without bound.
    """
    256

  fun min_max_packet(): U32 =>
    """
    Minimum peer channel packet size accepted by this implementation. Smaller
    limits would require too many outbound packets per application send.
    """
    256

  fun max_max_packet(): U32 =>
    """
    Ceiling for a peer's advertised channel packet size. Above the transport's
    own 35000-byte packet limit we would frame packets our own reader — and a
    conformant peer's — rejects. 32768 is the RFC 4253 §6.1 payload size.
    """
    32768

  fun supported_max_packet(value: U32): Bool =>
    """Whether a peer's packet size meets the supported minimum."""
    value >= min_max_packet()

  fun cap_max_packet(value: U32): U32 =>
    """Cap an accepted peer packet size to the transport's payload limit."""
    value.min(max_max_packet())

class SshChannelManager
  """
  Tracks channel state keyed by local channel id. The local id (the map key) is
  the value we advertise to the peer as `sender_channel`; the peer echoes it
  back as the `recipient_channel` of every message it sends us, so the
  connection layer uses an inbound `recipient_channel` directly as the local
  key. A channel's `remote_id` is stored only to fill the `recipient_channel`
  field of messages we send to the peer. Anyone changing how outbound messages
  are keyed must preserve this local-id == map-key == peer's recipient_channel
  invariant, or inbound routing will look up the wrong channel.
  """
  var _next_local_id: U32 = 0
  let initial_window: U32
  let _channels: Map[U32, SshChannelState] = Map[U32, SshChannelState]

  new create(initial_window': U32 = SshChannelWindow.initial()) =>
    """The receive window is at least 256 bytes, even for smaller inputs."""
    initial_window = initial_window'.max(SshChannelLimits.min_max_packet())

  fun ref open_channel(channel_type: String val): U32 =>
    """Allocate local channel ID and create pending state."""
    let id = _next_local_id
    _next_local_id = _next_local_id + 1
    _channels(id) = SshChannelState(id, 0, initial_window, 0, 0, channel_type)
    id

  fun ref confirm_channel(local_id: U32, remote_id: U32,
    remote_window: U32, max_packet_size: U32): (None | SshChannelError)
  =>
    """
    Confirm a pending channel open. The peer accepting the channel we opened is
    what authorizes it, so this is where a channel of ours becomes usable.
    """
    try
      let ch = _channels(local_id)?
      if not SshChannelLimits.supported_max_packet(max_packet_size) then
        return SshChannelUnsupportedPacketSize(max_packet_size,
          SshChannelLimits.min_max_packet())
      end
      ch.remote_id = remote_id
      ch.remote_window = remote_window
      ch.max_packet_size = SshChannelLimits.cap_max_packet(max_packet_size)
      ch.authorized = true
      None
    else
      SshChannelClosed
    end

  fun ref accept_channel(local_id: U32, remote_id: U32,
    remote_window: U32, max_packet_size: U32, channel_type: String val):
    (U32 | SshChannelUnsupportedPacketSize)
  =>
    """Accept an incoming channel open from remote (server side)."""
    if not SshChannelLimits.supported_max_packet(max_packet_size) then
      return SshChannelUnsupportedPacketSize(max_packet_size,
        SshChannelLimits.min_max_packet())
    end
    let id = _next_local_id
    _next_local_id = _next_local_id + 1
    _channels(id) = SshChannelState(id, remote_id, initial_window,
      remote_window, SshChannelLimits.cap_max_packet(max_packet_size),
      channel_type)
    id

  fun box channel_remote_id_if_open(local_id: U32):
    (U32 | SshChannelError)
  =>
    """Return the peer's channel ID when the local channel is open."""
    try
      let ch = _channels(local_id)?
      if not ch.open then return SshChannelClosed end
      ch.remote_id
    else
      SshChannelClosed
    end

  fun ref channel_data_admitted(local_id: U32, data_size: USize):
    (None | SshChannelError)
  =>
    """Debit the peer window after a segment has been admitted to transport."""
    try
      let ch = _channels(local_id)?
      if (not ch.open) or (not ch.authorized) then
        return SshChannelClosed
      end
      if data_size > U32.max_value().usize() then
        return SshWindowExhausted
      end
      if ch.remote_window < data_size.u32() then
        return SshWindowExhausted
      end
      ch.remote_window = ch.remote_window - data_size.u32()
      None
    else
      SshChannelClosed
    end

  fun ref clear_send_blocked() =>
    """Clear blocked-send state when the session ends."""
    for ch in _channels.values() do ch.send_blocked = false end

  fun ref channel_data_received(local_id: U32, data_size: USize):
    (U32 | SshChannelError)
  =>
    """
    Account for received data against the receive window. Returns the remaining
    window on success, or SshWindowExhausted if the peer sent more than the
    window we advertised (a flow-control violation we must not silently absorb).
    """
    try
      let ch = _channels(local_id)?
      if not ch.open then return SshChannelClosed end
      if ch.local_window < data_size.u32() then return SshWindowExhausted end
      ch.local_window = ch.local_window - data_size.u32()
      ch.local_window
    else
      SshChannelClosed
    end

  fun ref replenish_local_window(local_id: U32): (U32 | None) =>
    """
    If the receive window has fallen below half its initial size, top it back
    up to the initial size and return the increment to advertise to the peer
    via SSH_MSG_CHANNEL_WINDOW_ADJUST. Returns None when no adjustment is due.
    Without this the peer's send window decays to zero and the channel stalls.
    """
    try
      let ch = _channels(local_id)?
      let initial = initial_window
      if ch.local_window < (initial / 2) then
        let increment = initial - ch.local_window
        ch.local_window = ch.local_window + increment
        increment
      else
        None
      end
    else
      None
    end

  fun ref window_adjust(local_id: U32, bytes: U32) =>
    """
    Increase the remote send window for a channel. Saturates at U32 max rather
    than wrapping: a peer that sums WINDOW_ADJUSTs past 2^32 (which RFC 4254
    §5.2 forbids) must not silently wrap our window back to a small value.
    """
    try
      let ch = _channels(local_id)?
      (let sum, let overflow) = ch.remote_window.addc(bytes)
      ch.remote_window = if overflow then U32.max_value() else sum end
    end

  fun ref close_channel(local_id: U32) =>
    """Remove channel state."""
    try _channels.remove(local_id)? end

  fun ref get(local_id: U32): (SshChannelState ref | None) =>
    try _channels(local_id)? else None end

  fun channel_count(): USize =>
    _channels.size()

  fun at_capacity(): Bool =>
    """True once the concurrent-channel cap is reached; reject further opens."""
    _channels.size() >= SshChannelLimits.max_concurrent()
