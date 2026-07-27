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

class iso _TestChannelDataQueuedAcrossWindowAdjust is UnitTest
  fun name(): String => "ssh_channel/data_queued_across_window_adjust"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id = mgr.open_channel("session")
    mgr.confirm_channel(local_id, 10, 4, 3)

    match mgr.queue_channel_data(local_id, "abcdef".array())
    | None => None
    | let e: SshChannelError =>
      h.fail("could not queue first write: " + e.string())
    end
    match mgr.queue_channel_data(local_id, "gh".array())
    | None => None
    | let e: SshChannelError =>
      h.fail("could not queue second write: " + e.string())
    end

    match mgr.next_channel_data(local_id)
    | let s: SshChannelDataSegment val =>
      h.assert_eq[U32](10, s.remote_id)
      h.assert_array_eq[U8]("abc".array(), s.data)
    else h.fail("expected first packet-sized segment")
    end
    match mgr.next_channel_data(local_id)
    | let s: SshChannelDataSegment val =>
      h.assert_array_eq[U8]("d".array(), s.data)
    else h.fail("expected window-bounded segment")
    end
    h.assert_eq[USize](4, mgr.pending_send_bytes(local_id))
    match mgr.next_channel_data(local_id)
    | None => None
    else h.fail("expected flow control to pause delivery")
    end

    mgr.window_adjust(local_id, 10)
    match mgr.next_channel_data(local_id)
    | let s: SshChannelDataSegment val =>
      h.assert_array_eq[U8]("ef".array(), s.data)
    else h.fail("expected retained suffix after window adjustment")
    end
    match mgr.next_channel_data(local_id)
    | let s: SshChannelDataSegment val =>
      h.assert_array_eq[U8]("gh".array(), s.data)
    else h.fail("expected second write after retained suffix")
    end
    h.assert_eq[USize](0, mgr.pending_send_bytes(local_id))

class iso _TestChannelSendQueueBound is UnitTest
  fun name(): String => "ssh_channel/send_queue_bound"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager(4)
    let local_id = mgr.open_channel("session")
    mgr.confirm_channel(local_id, 10, 0, 3)

    match mgr.queue_channel_data(local_id, "abcd".array())
    | None => None
    | let e: SshChannelError => h.fail("could not fill queue: " + e.string())
    end
    match mgr.queue_channel_data(local_id, "e".array())
    | SshSendQueueFull => None
    else h.fail("expected an atomic queue-capacity error")
    end
    h.assert_eq[USize](4, mgr.pending_send_bytes(local_id))

    mgr.window_adjust(local_id, 2)
    match mgr.next_channel_data(local_id)
    | let s: SshChannelDataSegment val =>
      h.assert_array_eq[U8]("ab".array(), s.data)
    else h.fail("expected queued prefix")
    end
    match mgr.queue_channel_data(local_id, "e".array())
    | None => None
    | let e: SshChannelError => h.fail("capacity was not reclaimed: " + e.string())
    end
    h.assert_eq[USize](3, mgr.pending_send_bytes(local_id))

class iso _TestChannelClose is UnitTest
  fun name(): String => "ssh_channel/close"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id = mgr.open_channel("session")
    mgr.confirm_channel(local_id, 7, 0x100000, 0x8000)

    h.assert_eq[USize](1, mgr.channel_count())

    mgr.close_channel(local_id)

    h.assert_eq[USize](0, mgr.channel_count())

    match mgr.queue_channel_data(local_id, "closed".array())
    | SshChannelClosed => None
    | let e: SshChannelError =>
      h.fail("expected SshChannelClosed, got: " + e.string())
    | None => h.fail("expected SshChannelClosed")
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
