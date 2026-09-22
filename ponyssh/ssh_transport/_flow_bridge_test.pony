use "pony_test"
use "../ssh_auth"

class \nodoc\ iso _TestFlowNoBridgeSend is UnitTest
  fun name(): String => "ssh_transport/flow_no_bridge_send"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowNoBridgeNotify(h, false)

class \nodoc\ iso _TestFlowNoBridgeFlush is UnitTest
  fun name(): String => "ssh_transport/flow_no_bridge_flush"
  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowNoBridgeNotify(h, true)

actor \nodoc\ _FlowNoBridgeNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _flush: Bool
  let _data: Array[U8] val = recover val Array[U8].init(1, 100) end
  var _packets: USize = 0

  new create(h: TestHelper, flush: Bool) =>
    _h = h
    _flush = flush
    let session = SshSession._flow_test(this, this, 1000, 256, 10)
    if not flush then session._flow_end_blackout() end
    session.channel_send(0, _data)

  fun validate_password(username: String val, password: String val): Bool =>
    false
  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be _flow_admitted(payload: Array[U8] val) =>
    _packets = _packets + 1

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    if _flush then
      _h.assert_eq[USize](100, accepted)
      _h.assert_true(outcome is SshSendComplete)
      _h.assert_eq[USize](1, _packets)
      session._flow_end_blackout()
      session._flow_flush_without_bridge()
    else
      _h.assert_eq[USize](0, accepted)
      _h.assert_true(outcome is SshSendClosed)
      _h.assert_eq[USize](0, _packets)
    end
    session._flow_snapshot(this)

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_eq[USize](0, pending_packets)
    _h.assert_eq[USize](0, pending_bytes)
    _h.assert_eq[U32](if _flush then 900 else 1000 end, remote_window)
    _h.assert_true(terminated)
    _h.complete(true)

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be _flow_barrier() => None
