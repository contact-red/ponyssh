use "pony_test"
use "../ssh_auth"
use "../ssh_connection"

class \nodoc\ iso _TestFlowTerminalExplicit is UnitTest
  fun name(): String => "ssh_transport/flow_terminal_explicit"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowTerminalNotify(h, 0)

class \nodoc\ iso _TestFlowTerminalPeer is UnitTest
  fun name(): String => "ssh_transport/flow_terminal_peer"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowTerminalNotify(h, 1)

class \nodoc\ iso _TestFlowTerminalTcpClosed is UnitTest
  fun name(): String => "ssh_transport/flow_terminal_tcp_closed"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowTerminalNotify(h, 2)

class \nodoc\ iso _TestFlowTerminalTcpFailed is UnitTest
  fun name(): String => "ssh_transport/flow_terminal_tcp_failed"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowTerminalNotify(h, 3)

class \nodoc\ iso _TestFlowTerminalError is UnitTest
  fun name(): String => "ssh_transport/flow_terminal_error"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowTerminalNotify(h, 4)

actor \nodoc\ _FlowTerminalNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _kind: U8
  let _data: Array[U8] val = recover val Array[U8].init(9, 600) end
  var _packets: USize = 0

  new create(h: TestHelper, kind: U8) =>
    _h = h
    _kind = kind
    let session = SshSession._flow_test(this, this, 256, 256, 10)
    session.channel_send(0, _data)

  fun validate_password(username: String val, password: String val): Bool =>
    false
  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? == SshChannelMsgTypes.channel_data() then
        _packets = _packets + 1
      end
    else
      _h.fail("invalid queued terminal-test packet")
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _h.assert_eq[USize](256, accepted)
    _h.assert_true(outcome is SshSendWindowBlocked)
    _h.assert_eq[USize](1, _packets)
    if _kind == 0 then session.disconnect()
    else session._flow_terminate(_kind) end
    session._flow_snapshot(this)

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_eq[USize](0, pending_packets)
    _h.assert_eq[USize](0, pending_bytes)
    _h.assert_false(blocked)
    _h.assert_eq[U32](0, remote_window)
    _h.assert_true(terminated)
    _h.complete(true)

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("window hint after terminal cleanup")

  be _flow_barrier() => None

class \nodoc\ iso _TestFlowChannelClose is UnitTest
  fun name(): String => "ssh_transport/flow_channel_close"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowCloseNotify(h)

actor \nodoc\ _FlowCloseNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _session: SshSession tag
  var _closed: Bool = false
  var _snapshot_count: USize = 0

  new create(h: TestHelper) =>
    _h = h
    _session = SshSession._flow_test(this, this, 0, 256, 10)
    _session.channel_send(0, recover val [as U8: 1] end)

  fun validate_password(username: String val, password: String val): Bool =>
    false
  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _h.assert_eq[USize](0, accepted)
    _h.assert_true(outcome is SshSendWindowBlocked)
    session.channel_close(channel_id)
    session._flow_dispatch_grants(recover val [as U32: 1] end, this)
    session._flow_snapshot(this)

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) =>
    _closed = true

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("window hint after channel close")

  be _flow_barrier() => _h.assert_true(_closed)

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_false(blocked)
    _h.assert_eq[U32](0, remote_window)
    if _snapshot_count == 0 then
      _h.assert_false(terminated)
      _h.assert_eq[USize](2, pending_packets)
      _snapshot_count = 1
      _session.disconnect()
      _session._flow_snapshot(this)
    else
      _h.assert_true(terminated)
      _h.assert_eq[USize](0, pending_packets)
      _h.assert_eq[USize](0, pending_bytes)
      _h.complete(true)
    end

  be _flow_admitted(payload: Array[U8] val) => None
