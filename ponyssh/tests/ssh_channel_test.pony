use "pony_test"
use "../ssh_connection"
use "../ssh_transport"
use "../ssh_error"

class iso _TestChannelOpenAndConfirm is UnitTest
  fun name(): String => "ssh_channel/open_and_confirm"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id = mgr.open_channel("session")

    h.assert_eq[U32](0, local_id)
    h.assert_eq[USize](1, mgr.channel_count())

    let result = mgr.confirm_channel(local_id, 42, 0x100000, 0x8000)
    match result
    | None => None
    | let e: SshChannelError => h.fail("expected None, got error: " + e.string())
    end

    match mgr.get(local_id)
    | let ch: SshChannelState =>
      h.assert_eq[U32](local_id, ch.local_id)
      h.assert_eq[U32](42, ch.remote_id)
      h.assert_eq[U32](0x200000, ch.local_window)
      h.assert_eq[U32](0x100000, ch.remote_window)
      h.assert_eq[U32](0x8000, ch.max_packet_size)
    | None => h.fail("channel not found after confirm")
    end

class iso _TestChannelDataSendWindowTracking is UnitTest
  fun name(): String => "ssh_channel/data_send_window_tracking"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id = mgr.open_channel("session")
    mgr.confirm_channel(local_id, 10, 100, 0x8000)

    // Send 50 bytes — should succeed, window goes from 100 to 50
    match mgr.channel_data_send(local_id, 50)
    | let remote_id: U32 =>
      h.assert_eq[U32](10, remote_id)
    | let e: SshChannelError =>
      h.fail("expected remote_id, got error: " + e.string())
    end

    match mgr.get(local_id)
    | let ch: SshChannelState => h.assert_eq[U32](50, ch.remote_window)
    | None => h.fail("channel not found")
    end

    // Send 60 bytes — should fail with SshWindowExhausted (window is 50)
    match mgr.channel_data_send(local_id, 60)
    | let remote_id: U32 => h.fail("expected SshWindowExhausted, got remote_id")
    | SshWindowExhausted => None
    | let e: SshChannelError =>
      h.fail("expected SshWindowExhausted, got: " + e.string())
    end

    // Window adjust +100 brings remote_window to 150
    mgr.window_adjust(local_id, 100)

    match mgr.get(local_id)
    | let ch: SshChannelState => h.assert_eq[U32](150, ch.remote_window)
    | None => h.fail("channel not found")
    end

    // Now send 60 bytes — should succeed
    match mgr.channel_data_send(local_id, 60)
    | let remote_id: U32 =>
      h.assert_eq[U32](10, remote_id)
    | let e: SshChannelError =>
      h.fail("expected remote_id after window adjust, got: " + e.string())
    end

class iso _TestChannelClose is UnitTest
  fun name(): String => "ssh_channel/close"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id = mgr.open_channel("session")
    mgr.confirm_channel(local_id, 7, 0x100000, 0x8000)

    h.assert_eq[USize](1, mgr.channel_count())

    mgr.close_channel(local_id)

    h.assert_eq[USize](0, mgr.channel_count())

    match mgr.channel_data_send(local_id, 10)
    | let remote_id: U32 => h.fail("expected SshChannelClosed, got remote_id")
    | SshChannelClosed => None
    | let e: SshChannelError =>
      h.fail("expected SshChannelClosed, got: " + e.string())
    end

class iso _TestChannelCapacity is UnitTest
  """
  at_capacity() reports false below the concurrent-channel cap and true once it
  is reached, so the session can reject further CHANNEL_OPENs before allocating
  state (the bound that stops a CHANNEL_OPEN-flood memory DoS).
  """
  fun name(): String => "ssh_channel/capacity_cap"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    h.assert_false(mgr.at_capacity())

    var i: USize = 0
    while i < SshChannelLimits.max_concurrent() do
      mgr.accept_channel(0, i.u32(), 0x100000, 0x8000, "session")
      // Capacity must not be reported until the final accept brings us to the
      // cap, or the session would reject a legal channel one short of the limit.
      if (i + 1) < SshChannelLimits.max_concurrent() then
        h.assert_false(mgr.at_capacity())
      end
      i = i + 1
    end

    h.assert_eq[USize](SshChannelLimits.max_concurrent(), mgr.channel_count())
    h.assert_true(mgr.at_capacity())

primitive _ChannelBytes
  fun apply(size: USize): Array[U8] val =>
    """
    A byte pattern whose value changes with position, so a test that reassembles
    it detects bytes delivered out of order, not just the right count.
    """
    recover val
      let a = Array[U8](size)
      var i: USize = 0
      while i < size do
        a.push((i % 251).u8())
        i = i + 1
      end
      a
    end

primitive _ChannelDrain
  fun segments(mgr: SshChannelManager ref, id: U32): Array[Array[U8] val] =>
    """Every segment the manager will release right now, in order."""
    let out = Array[Array[U8] val]
    var draining = true
    while draining do
      match mgr.next_send_segment(id)
      | let seg: Array[U8] val => out.push(seg)
      | None => draining = false
      end
    end
    out

  fun joined(mgr: SshChannelManager ref, id: U32): Array[U8] val =>
    """Those segments concatenated, as the peer would see them."""
    let out = recover iso Array[U8] end
    for seg in segments(mgr, id).values() do
      out.append(seg)
    end
    consume out

class iso _TestChannelSendSurvivesWindowExhaustion is UnitTest
  """
  Data offered beyond the peer's send window is held and delivered once the peer
  grants more, byte for byte and in order. Before the send queue existed the
  tail past the window was dropped and the caller was told only that the window
  was exhausted, with no way to learn how much had gone out.
  """
  fun name(): String => "ssh_channel/send_survives_window_exhaustion"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let id = mgr.open_channel("session")
    // A 100-byte send window and 32-byte packets: 250 bytes cannot go out in
    // one pass, so the queue has to hold the rest.
    mgr.confirm_channel(id, 4, 100, 32)

    let data = _ChannelBytes(250)
    match mgr.queue_send(id, data)
    | let e: SshChannelError => h.fail("queue must accept: " + e.string())
    end

    // Only what the window allows leaves now; the rest stays queued.
    let first = _ChannelDrain.joined(mgr, id)
    h.assert_eq[USize](100, first.size())
    h.assert_eq[USize](150, mgr.pending_send_bytes(id))

    mgr.window_adjust(id, 1000)
    let second = _ChannelDrain.joined(mgr, id)
    h.assert_eq[USize](150, second.size())
    h.assert_eq[USize](0, mgr.pending_send_bytes(id))

    let delivered = recover iso Array[U8] end
    delivered.append(first)
    delivered.append(second)
    let all: Array[U8] val = consume delivered
    h.assert_array_eq[U8](data, all)

class iso _TestChannelSendQueueAllOrNothing is UnitTest
  """
  A write the queue cannot hold whole is refused outright and nothing is queued,
  so a caller is never left working out which part of its buffer went out.
  """
  fun name(): String => "ssh_channel/send_queue_all_or_nothing"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let id = mgr.open_channel("session")
    // No send window, so everything offered stays queued.
    mgr.confirm_channel(id, 4, 0, 32)

    let cap = SshChannelLimits.max_pending_send()
    match mgr.queue_send(id, _ChannelBytes(cap))
    | let e: SshChannelError => h.fail("a write that fills the queue must fit")
    end
    h.assert_eq[USize](cap, mgr.pending_send_bytes(id))

    match mgr.queue_send(id, _ChannelBytes(1))
    | SshWindowExhausted => None
    | let e: SshChannelError => h.fail("expected SshWindowExhausted")
    | None => h.fail("a write past the cap must be refused")
    end
    // Refused whole: the byte over the cap left no trace.
    h.assert_eq[USize](cap, mgr.pending_send_bytes(id))

class iso _TestChannelSendSegmentBounds is UnitTest
  """
  No segment exceeds the peer's maximum packet size — a conformant peer rejects
  an oversized CHANNEL_DATA — and the bytes reassemble exactly whatever the
  relationship between the queued length and that size.
  """
  fun name(): String => "ssh_channel/send_segment_bounds"

  fun apply(h: TestHelper) =>
    // Below one packet, exactly one, an exact multiple, and a ragged remainder.
    let cases = [as (USize, USize): (1, 16); (16, 16); (64, 16); (65, 16)]
    for (total, max_packet) in cases.values() do
      let mgr: SshChannelManager ref = SshChannelManager
      let id = mgr.open_channel("session")
      mgr.confirm_channel(id, 4, 100000, max_packet.u32())

      let data = _ChannelBytes(total)
      mgr.queue_send(id, data)

      let segments = _ChannelDrain.segments(mgr, id)
      let joined = recover iso Array[U8] end
      for seg in segments.values() do
        h.assert_true(seg.size() <= max_packet,
          "segment of " + seg.size().string() + " exceeds max packet "
            + max_packet.string())
        joined.append(seg)
      end
      let all: Array[U8] val = consume joined
      h.assert_array_eq[U8](data, all)
    end

class iso _TestChannelSendUnblockedReportedOnce is UnitTest
  """
  The drained-empty signal is raised only for a channel whose write was refused,
  and only once, so a consumer that never overflowed is never woken and one that
  did is not woken repeatedly.
  """
  fun name(): String => "ssh_channel/send_unblocked_once"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let cap = SshChannelLimits.max_pending_send()

    // A channel that queues and drains without ever being refused.
    let quiet = mgr.open_channel("session")
    mgr.confirm_channel(quiet, 4, 0, 32)
    mgr.queue_send(quiet, _ChannelBytes(64))
    mgr.window_adjust(quiet, 1000)
    _ChannelDrain.joined(mgr, quiet)
    h.assert_eq[USize](0, mgr.pending_send_bytes(quiet))
    h.assert_false(mgr.take_send_unblocked(quiet))

    // A channel that fills its queue, is refused, then drains empty.
    let noisy = mgr.open_channel("session")
    mgr.confirm_channel(noisy, 5, 0, 32)
    mgr.queue_send(noisy, _ChannelBytes(cap))
    match mgr.queue_send(noisy, _ChannelBytes(1))
    | SshWindowExhausted => None
    else
      h.fail("a write past the cap must be refused")
    end

    // Still queued: nothing to report until it has actually drained.
    h.assert_false(mgr.take_send_unblocked(noisy))

    mgr.window_adjust(noisy, cap.u32())
    _ChannelDrain.joined(mgr, noisy)
    h.assert_eq[USize](0, mgr.pending_send_bytes(noisy))
    h.assert_true(mgr.take_send_unblocked(noisy))
    // Reported once and cleared, so the consumer is not woken again.
    h.assert_false(mgr.take_send_unblocked(noisy))

class iso _TestChannelSendQueueRejectsUnknownChannel is UnitTest
  """
  Queuing for a channel that does not exist is a closed-channel error, not a
  silent discard.
  """
  fun name(): String => "ssh_channel/send_queue_unknown_channel"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    match mgr.queue_send(99, _ChannelBytes(4))
    | SshChannelClosed => None
    | let e: SshChannelError => h.fail("expected SshChannelClosed")
    | None => h.fail("queuing for an unknown channel must fail")
    end

class iso _TestChannelRequestExecEncode is UnitTest
  """
  The exec channel-request encoder lays out the exact RFC 4254 §6.5 wire
  fields a client uses to run a command.
  """
  fun name(): String => "ssh_channel/request_exec_encode"

  fun apply(h: TestHelper) =>
    let msg = SshChannelMessages.channel_request_exec(7, "ls -l", true)
    try
      let r = SshWireReader(msg)
      h.assert_eq[U8](SshChannelMsgTypes.channel_request(), r.read_byte()?)
      h.assert_eq[U32](7, r.read_u32()?)
      h.assert_eq[String val]("exec", r.read_string_as_str()?)
      h.assert_eq[Bool](true, r.read_bool()?)
      h.assert_eq[String val]("ls -l", r.read_string_as_str()?)
    else
      h.fail("could not decode exec request")
    end

class iso _TestChannelRequestShellEncode is UnitTest
  """
  The shell channel-request encoder lays out the exact RFC 4254 §6.5 wire
  fields a client uses to start a login shell.
  """
  fun name(): String => "ssh_channel/request_shell_encode"

  fun apply(h: TestHelper) =>
    let msg = SshChannelMessages.channel_request_shell(3, false)
    try
      let r = SshWireReader(msg)
      h.assert_eq[U8](SshChannelMsgTypes.channel_request(), r.read_byte()?)
      h.assert_eq[U32](3, r.read_u32()?)
      h.assert_eq[String val]("shell", r.read_string_as_str()?)
      h.assert_eq[Bool](false, r.read_bool()?)
    else
      h.fail("could not decode shell request")
    end
