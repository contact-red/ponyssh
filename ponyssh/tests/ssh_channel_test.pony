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

class iso _TestChannelMaxPacketSizeClamped is UnitTest
  """
  max_packet_size arrives as a peer-controlled uint32 on CHANNEL_OPEN and
  CHANNEL_OPEN_CONFIRMATION, and it divides our outbound channel data. A peer
  advertising 1 makes every byte of application output its own SSH packet — 36
  bytes on the wire and a full AEAD operation per byte, from a single 4-byte
  field. A peer advertising more than the transport's own packet limit makes us
  frame packets our own reader would reject. Both ends are clamped when the
  value is stored, so _channel_send_segmented can divide by it without
  re-checking.
  """
  fun name(): String => "ssh_channel/max_packet_size_clamped"

  fun apply(h: TestHelper) =>
    // (advertised, expected) — the boundaries are the clamp's own bounds: 256 is
    // the floor, 32768 the RFC 4253 §6.1 payload every implementation accepts.
    let cases: Array[(U32, U32)] val =
      [ (0, 256); (1, 256); (255, 256); (256, 256)
        (257, 257); (4096, 4096); (32767, 32767); (32768, 32768)
        (32769, 32768); (100000, 32768); (U32.max_value(), 32768) ]

    for (advertised, expected) in cases.values() do
      // The accept path: the peer opened the channel and named the value.
      let accept_mgr: SshChannelManager ref = SshChannelManager
      let accepted = accept_mgr.accept_channel(0, 7, 0x100000, advertised,
        "session")
      match accept_mgr.get(accepted)
      | let ch: SshChannelState =>
        h.assert_eq[U32](expected, ch.max_packet_size,
          "accept_channel did not clamp " + advertised.string())
      | None => h.fail("accepted channel not found")
      end

      // The confirm path: we opened the channel and the peer named the value.
      let confirm_mgr: SshChannelManager ref = SshChannelManager
      let opened = confirm_mgr.open_channel("session")
      confirm_mgr.confirm_channel(opened, 7, 0x100000, advertised)
      match confirm_mgr.get(opened)
      | let ch: SshChannelState =>
        h.assert_eq[U32](expected, ch.max_packet_size,
          "confirm_channel did not clamp " + advertised.string())
      | None => h.fail("confirmed channel not found")
      end
    end

class iso _TestChannelAuthorizedOnlyAfterDecision is UnitTest
  """
  A channel the peer asked us to open exists before it is authorized: state is
  allocated when CHANNEL_OPEN is parsed, but the consumer's accept/reject is an
  asynchronous behavior and a whole TCP segment is dispatched before it can run.
  The session refuses requests and data on a channel that is not yet authorized,
  which depends on accept_channel leaving the flag clear. A channel we opened
  ourselves is authorized by the peer's CHANNEL_OPEN_CONFIRMATION instead.
  """
  fun name(): String => "ssh_channel/authorized_only_after_decision"

  fun apply(h: TestHelper) =>
    // Inbound: allocated unauthorized, and nothing in the manager grants it.
    let inbound: SshChannelManager ref = SshChannelManager
    let accepted = inbound.accept_channel(0, 7, 0x100000, 0x8000, "session")
    match inbound.get(accepted)
    | let ch: SshChannelState =>
      h.assert_false(ch.authorized,
        "a channel the peer opened must not be authorized before the consumer "
          + "decides")
    | None => h.fail("accepted channel not found")
    end

    // Outbound: ours, and the peer's confirmation is what authorizes it.
    let outbound: SshChannelManager ref = SshChannelManager
    let opened = outbound.open_channel("session")
    match outbound.get(opened)
    | let ch: SshChannelState =>
      h.assert_false(ch.authorized,
        "a channel we opened must not be authorized before the peer confirms")
    | None => h.fail("opened channel not found")
    end
    outbound.confirm_channel(opened, 7, 0x100000, 0x8000)
    match outbound.get(opened)
    | let ch: SshChannelState =>
      h.assert_true(ch.authorized,
        "CHANNEL_OPEN_CONFIRMATION must authorize a channel we opened")
    | None => h.fail("confirmed channel not found")
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
