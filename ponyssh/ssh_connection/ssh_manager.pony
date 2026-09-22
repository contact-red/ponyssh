use "collections"
use "../ssh_error"

primitive SshChannelWindow
  """The receive window ponyssh advertises for each channel it opens/accepts."""
  fun initial(): U32 => 0x200000  // 2 MiB

primitive SshChannelLimits
  """
  Bounds on channel state, enforced so a hostile peer cannot grow it without
  bound.
  """
  fun max_concurrent(): USize =>
    """
    Maximum number of channels held at once. Each accepted CHANNEL_OPEN
    allocates state advertising a 2 MiB window; without a cap a peer flooding
    CHANNEL_OPEN could exhaust memory. 256 is generous for legitimate use.
    """
    256

  fun min_max_packet(): U32 =>
    """
    Floor for a peer's advertised channel packet size. The peer picks this value
    off the wire, and it divides our outbound data: at 1 byte per packet each
    byte of application output costs a 36-byte frame and a full AEAD operation.
    256 keeps that overhead bounded while staying far below any size a real
    implementation asks for, and well inside the 32768-byte payload RFC 4253
    §6.1 requires every implementation to accept.
    """
    256

  fun max_max_packet(): U32 =>
    """
    Ceiling for a peer's advertised channel packet size. Above the transport's
    own 35000-byte packet limit we would frame packets our own reader — and a
    conformant peer's — rejects. 32768 is the RFC 4253 §6.1 payload size.
    """
    32768

  fun clamp_max_packet(value: U32): U32 =>
    """Bring a peer-advertised channel packet size within the bounds above."""
    value.max(min_max_packet()).min(max_max_packet())

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
  let _channels: Map[U32, SshChannelState] = Map[U32, SshChannelState]

  fun ref open_channel(channel_type: String val): U32 =>
    """Allocate local channel ID and create pending state."""
    let id = _next_local_id
    _next_local_id = _next_local_id + 1
    let initial_window: U32 = SshChannelWindow.initial()
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
      ch.remote_id = remote_id
      ch.remote_window = remote_window
      ch.max_packet_size = SshChannelLimits.clamp_max_packet(max_packet_size)
      ch.authorized = true
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
    let initial_window: U32 = SshChannelWindow.initial()
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

  fun ref channel_send_candidate(local_id: U32):
    (SshChannelState ref | SshChannelError)
  =>
    """Return an authorized channel for a data send or local close."""
    try
      let ch = _channels(local_id)?
      if (not ch.open) or (not ch.authorized) then
        return SshChannelClosed
      end
      ch
    else
      SshChannelClosed
    end

  fun ref channel_data_admitted(local_id: U32, data_size: USize) =>
    """Debit the peer window after a segment has been admitted to transport."""
    try
      let ch = _channels(local_id)?
      ch.remote_window = ch.remote_window - data_size.u32()
    end

  fun ref clear_send_blocked() =>
    """Release all pending window hints when the session ends."""
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
      let initial = SshChannelWindow.initial()
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
