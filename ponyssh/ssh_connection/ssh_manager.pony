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

  fun max_pending_send(): USize =>
    """
    Maximum outbound bytes held per channel while waiting on the peer's send
    window. The queue exists to cover the round trip between exhausting that
    window and the CHANNEL_WINDOW_ADJUST that reopens it, so it needs to absorb
    a burst, not a whole transfer. 256 KiB does that while bounding a peer that
    stops granting window at 64 MiB across the 256-channel cap.
    """
    262144

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

  fun ref queue_send(local_id: U32, data: Array[U8] val):
    (None | SshChannelError)
  =>
    """
    Take outbound channel data, to be drained as the peer's send window allows.
    All of data is accepted or none of it is: when the queue has no room for the
    whole buffer the call is rejected with SshWindowExhausted and nothing is
    queued, so a caller is never left working out how much of its buffer went
    out. SshChannelClosed means there is no such open channel.
    """
    try
      let ch = _channels(local_id)?
      if not ch.open then return SshChannelClosed end
      if data.size() == 0 then return None end
      if (ch.pending_bytes + data.size()) > SshChannelLimits.max_pending_send()
      then
        ch.send_blocked = true
        return SshWindowExhausted
      end
      ch.pending_send.push(data)
      ch.pending_bytes = ch.pending_bytes + data.size()
      None
    else
      SshChannelClosed
    end

  fun ref next_send_segment(local_id: U32): (Array[U8] val | None) =>
    """
    Take the next segment of queued outbound data that the peer's send window
    and maximum packet size allow, charging it against the window. The result is
    a view into the queued buffer, not a copy. None once the queue is empty or
    the window is full, leaving the remainder to wait for the peer's next
    CHANNEL_WINDOW_ADJUST.
    """
    try
      let ch = _channels(local_id)?
      if not ch.open then return None end
      let head = ch.pending_send.head()?()?
      let window = ch.remote_window.usize()
      if window == 0 then return None end
      let seg_len = head.size().min(_max_packet_size(ch)).min(window)
      // Charge the window through the one method that owns that accounting.
      match channel_data_send(local_id, seg_len)
      | let _: SshChannelError => return None
      end
      ch.pending_send.shift()?
      if seg_len < head.size() then
        ch.pending_send.unshift(head.trim(seg_len))
      end
      ch.pending_bytes = ch.pending_bytes - seg_len
      head.trim(0, seg_len)
    else
      None
    end

  fun ref take_send_unblocked(local_id: U32): Bool =>
    """
    True the once, when a channel whose queue was full has drained empty. The
    session reports that transition so a consumer whose write was refused knows
    it may resume; a consumer that never overflowed is never told anything.
    """
    try
      let ch = _channels(local_id)?
      if ch.send_blocked and (ch.pending_bytes == 0) then
        ch.send_blocked = false
        true
      else
        false
      end
    else
      false
    end

  fun pending_send_bytes(local_id: U32): USize =>
    """Outbound bytes still queued for a channel; 0 if there is no such channel."""
    try _channels(local_id)?.pending_bytes else 0 end

  fun _max_packet_size(ch: SshChannelState box): USize =>
    """
    The peer's maximum packet size, or 32 KiB when it advertised none — sending
    a larger CHANNEL_DATA than the peer allows is rejected by a conformant peer.
    """
    let m = ch.max_packet_size.usize()
    if m == 0 then 32768 else m end

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
