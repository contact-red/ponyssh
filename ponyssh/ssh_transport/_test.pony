use "pony_test"
use "collections"
use "../ssh_auth"
use "../ssh_connection"

actor \nodoc\ Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestFlowRetry)
    test(_TestFlowQueueLimit)
    test(_TestFlowBoundaries)
    test(_TestFlowNotReady)
    test(_TestFlowPacketLimit)
    test(_TestFlowPrefixConservation)
    test(_TestFlowGeneratedPrefix)
    test(_TestFlowGeneratedRetry)
    test(_TestFlowTerminalExplicit)
    test(_TestFlowTerminalPeer)
    test(_TestFlowTerminalTcpClosed)
    test(_TestFlowTerminalTcpFailed)
    test(_TestFlowTerminalError)
    test(_TestFlowChannelClose)
    test(_TestFlowNoBridgeSend)
    test(_TestFlowNoBridgeFlush)
    test(_TestFlowPeerPacketRejection)

class \nodoc\ _TestFlowRetry is UnitTest
  fun name(): String => "ssh_transport/flow_retry"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowRetryNotify(h)

actor \nodoc\ _FlowRetryNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _data: Array[U8] val = recover val
    let data = Array[U8]
    for i in Range[USize](0, 400) do data.push(i.u8()) end
    data
  end
  var _phase: USize = 0
  var _hints: USize = 0
  var _packets: USize = 0

  new create(h: TestHelper) =>
    _h = h
    let session = SshSession._flow_test(this, this, 300, 256, 10)
    session.channel_send(0, _data)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be _flow_admitted(payload: Array[U8] val) =>
    if payload.size() == 0 then
      _h.fail("empty queued packet")
      return
    end
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? != SshChannelMsgTypes.channel_data() then
        return
      end
      _h.assert_eq[U32](7, reader.read_u32()?)
      let bytes = reader.read_string()?
      let expected_offset: USize = if _packets == 0 then 0
        elseif _packets == 1 then 256
        elseif _packets == 2 then 300
        else 370 end
      let expected_size: USize = if _packets == 0 then 256
        elseif _packets == 1 then 44
        elseif _packets == 2 then 70
        else 30 end
      _h.assert_eq[USize](expected_size, bytes.size())
      for i in Range[USize](0, bytes.size()) do
        _h.assert_eq[U8](_data(expected_offset + i)?, bytes(i)?)
      end
      _packets = _packets + 1
    else
      _h.fail("invalid queued channel-data packet")
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _h.assert_eq[U32](0, channel_id)
    if _phase == 0 then
      _h.assert_true(data is _data)
      _h.assert_eq[USize](300, accepted)
      _h.assert_true(outcome is SshSendWindowBlocked)
      _h.assert_eq[USize](2, _packets)
      _phase = 1
      session._flow_dispatch_grants(recover val [as U32: 50; 20] end, this)
    elseif _phase == 1 then
      _h.assert_eq[USize](70, accepted)
      _h.assert_true(outcome is SshSendWindowBlocked)
      _phase = 2
      session._flow_dispatch_grants(recover val [as U32: 0; 30; 30] end,
        this)
    else
      _h.assert_eq[USize](30, accepted)
      _h.assert_true(outcome is SshSendComplete)
      _h.assert_eq[USize](4, _packets)
      session.disconnect()
      session._flow_snapshot(this)
    end

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32)
  =>
    _hints = _hints + 1
    if _hints == 1 then
      session.channel_send(channel_id, _data.trim(300))
    elseif _hints == 2 then
      session.channel_send(channel_id, _data.trim(370))
    else
      _h.fail("duplicate window hint")
    end

  be _flow_barrier() =>
    _h.assert_eq[USize](_phase, _hints)

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_eq[USize](0, pending_packets)
    _h.assert_eq[USize](0, pending_bytes)
    _h.assert_false(blocked)
    _h.assert_eq[U32](30, remote_window)
    _h.assert_true(terminated)
    _h.complete(true)

class \nodoc\ _TestFlowQueueLimit is UnitTest
  fun name(): String => "ssh_transport/flow_queue_limit"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowQueueLimitNotify(h)

actor \nodoc\ _FlowQueueLimitNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _data: Array[U8] val = recover val Array[U8].init(65, 900) end
  var _packets: USize = 0

  new create(h: TestHelper) =>
    _h = h
    let session = SshSession._flow_test(this, this, 1000, 256, 2)
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
    _h.assert_true(data is _data)
    _h.assert_eq[USize](512, accepted)
    _h.assert_true(outcome is SshSendClosed)
    _h.assert_eq[USize](2, _packets)
    session._flow_snapshot(this)

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be _flow_barrier() => None

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_eq[USize](0, pending_packets)
    _h.assert_eq[USize](0, pending_bytes)
    _h.assert_false(blocked)
    _h.assert_eq[U32](488, remote_window)
    _h.assert_true(terminated)
    _h.complete(true)

class \nodoc\ _TestFlowBoundaries is UnitTest
  fun name(): String => "ssh_transport/flow_boundaries"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowBoundariesNotify(h)

actor \nodoc\ _FlowBoundariesNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _empty: Array[U8] val = recover val Array[U8] end
  let _full: Array[U8] val = recover val Array[U8].init(42, 32768) end
  let _too_large: Array[U8] val =
    recover val Array[U8].init(43, 32769) end
  var _phase: USize = 0
  var _packets: USize = 0

  new create(h: TestHelper) =>
    _h = h
    let session = SshSession._flow_test(this, this, 32768, 32768, 10)
    session.channel_send(0, _empty)
    session.channel_send(0, _too_large)
    session.channel_send(0, _full)
    session.channel_send(1, _empty)
    session.disconnect()
    session.channel_send(0, _empty)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? == SshChannelMsgTypes.channel_data() then
        _h.assert_eq[U32](7, reader.read_u32()?)
        _h.assert_eq[USize](32768, reader.read_string()?.size())
        _packets = _packets + 1
      end
    else
      _h.fail("invalid queued packet")
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    if _phase == 0 then
      _h.assert_true(data is _empty)
      _h.assert_eq[USize](0, accepted)
      _h.assert_true(outcome is SshSendComplete)
    elseif _phase == 1 then
      _h.assert_true(data is _too_large)
      _h.assert_eq[USize](0, accepted)
      _h.assert_true(outcome is SshSendTooLarge)
    elseif _phase == 2 then
      _h.assert_true(data is _full)
      _h.assert_eq[USize](32768, accepted)
      _h.assert_true(outcome is SshSendComplete)
      _h.assert_eq[USize](1, _packets)
    elseif _phase == 3 then
      _h.assert_eq[U32](1, channel_id)
      _h.assert_eq[USize](0, accepted)
      _h.assert_true(outcome is SshSendClosed)
    else
      _h.assert_eq[U32](0, channel_id)
      _h.assert_eq[USize](0, accepted)
      _h.assert_true(outcome is SshSendClosed)
      _h.complete(true)
    end
    _phase = _phase + 1

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be _flow_barrier() => None

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool) => None

class \nodoc\ _TestFlowNotReady is UnitTest
  fun name(): String => "ssh_transport/flow_not_ready"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowNotReadyNotify(h)

actor \nodoc\ _FlowNotReadyNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _data: Array[U8] val = recover val [as U8: 1] end

  new create(h: TestHelper) =>
    _h = h
    let session = SshSession._flow_test(this, this, 100, 256, 10, false)
    session.channel_send(0, _data)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? == SshChannelMsgTypes.channel_data() then
        _h.fail("data admitted before channel authorization")
      end
    else
      _h.fail("invalid queued packet")
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _h.assert_true(data is _data)
    _h.assert_eq[USize](0, accepted)
    _h.assert_true(outcome is SshSendNotReady)
    session.disconnect()
    _h.complete(true)

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be _flow_barrier() => None

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool) => None
