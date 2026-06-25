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

class iso _TestChannelFindByRemoteId is UnitTest
  fun name(): String => "ssh_channel/find_by_remote_id"

  fun apply(h: TestHelper) =>
    var mgr: SshChannelManager ref = SshChannelManager
    let local_id_a = mgr.open_channel("session")
    let local_id_b = mgr.open_channel("session")
    mgr.confirm_channel(local_id_a, 100, 0x100000, 0x8000)
    mgr.confirm_channel(local_id_b, 200, 0x100000, 0x8000)

    match mgr.find_by_remote_id(100)
    | let found: U32 => h.assert_eq[U32](local_id_a, found)
    | None => h.fail("expected to find channel for remote_id 100")
    end

    match mgr.find_by_remote_id(200)
    | let found: U32 => h.assert_eq[U32](local_id_b, found)
    | None => h.fail("expected to find channel for remote_id 200")
    end

    match mgr.find_by_remote_id(999)
    | let found: U32 => h.fail("expected None for unknown remote_id 999")
    | None => None
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
