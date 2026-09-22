use "pony_test"
use "collections"
use "random"
use "../ssh_auth"
use "../ssh_connection"

class \nodoc\ iso _TestFlowGeneratedPrefix is UnitTest
  fun name(): String => "ssh_transport/flow_generated_prefix"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)
    _FlowGeneratedPrefixNotify(h)

actor \nodoc\ _FlowGeneratedPrefixNotify is
  (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _cases: Array[(U32, USize, U32)] = Array[(U32, USize, U32)]
  var _case: USize = 0
  var _data: Array[U8] val = recover val Array[U8] end
  var _admitted: USize = 0
  var _packets: USize = 0
  var _results: USize = 0
  var _session: (SshSession tag | None) = None
  var _saw_blocked: Bool = false
  var _saw_complete: Bool = false
  var _saw_too_large: Bool = false

  new create(h: TestHelper) =>
    _h = h
    for cap in [as U32: 256; 512; 32768].values() do
      let length: USize = (cap.usize() + 1).min(32768)
      for credit in [as U32: 0; cap - 1; cap; cap + 1
        length.u32() - 1; length.u32()].values() do
        _cases.push((credit, length, cap))
      end
    end
    _cases.push((0, 0, 256))
    _cases.push((32768, 32768, 32768))
    _cases.push((32768, 32769, 256))
    _cases.push((32768, 35000, 512))
    let rng = Rand(0x52f10a7)
    for i in Range[USize](0, 30) do
      let cap: U32 = 256 + (rng.u32() % 769)
      let length: USize = (rng.u32() % 4097).usize()
      let credit: U32 = rng.u32() % 4097
      _cases.push((credit, length, cap))
    end
    _run_case()

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  fun ref _run_case() =>
    try
      (let credit, let length, let cap) = _cases(_case)?
      _data = recover val
        let bytes = Array[U8].create(length)
        for i in Range[USize](0, length) do
          bytes.push(((i.u64() * 73) xor (i.u64() >> 3) xor
            (_case.u64() * 131)).u8())
        end
        bytes
      end
      _admitted = 0
      _packets = 0
      _results = 0
      let session = SshSession._flow_test(this, this, credit, cap, 200)
      _session = session
      session.channel_send(0, _data)
    else
      _h.assert_true(_saw_blocked)
      _h.assert_true(_saw_complete)
      _h.assert_true(_saw_too_large)
      _h.complete(true)
    end

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? != SshChannelMsgTypes.channel_data() then
        return
      end
      _h.assert_eq[U32](7, reader.read_u32()?)
      let bytes = reader.read_string()?
      (_, _, let cap) = _cases(_case)?
      _h.assert_true((bytes.size() > 0) and
        (bytes.size() <= cap.usize().min(32768)),
        "packet bound, seed 0x52f10a7 case " + _case.string())
      for i in Range[USize](0, bytes.size()) do
        if bytes(i)? != _data(_admitted + i)? then
          _h.fail("prefix bytes, seed 0x52f10a7 case " + _case.string())
          return
        end
      end
      _admitted = _admitted + bytes.size()
      _packets = _packets + 1
    else
      _h.fail("packet or expected data, seed 0x52f10a7 case " +
        _case.string())
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    try
      (let credit, let length, _) = _cases(_case)?
      _results = _results + 1
      _h.assert_eq[USize](1, _results)
      _h.assert_eq[U32](0, channel_id)
      _h.assert_true(data is _data)
      let expected: USize = if length > 32768 then 0
        else length.min(credit.usize()) end
      _h.assert_eq[USize](expected, accepted,
        "accepted, seed 0x52f10a7 case " + _case.string())
      _h.assert_eq[USize](expected, _admitted,
        "prefix length, seed 0x52f10a7 case " + _case.string())
      if length > 32768 then
        _h.assert_true(outcome is SshSendTooLarge)
        _saw_too_large = true
      elseif length > credit.usize() then
        _h.assert_true(outcome is SshSendWindowBlocked)
        _saw_blocked = true
      else
        _h.assert_true(outcome is SshSendComplete)
        _saw_complete = true
      end
      if expected == 0 then _h.assert_eq[USize](0, _packets) end
      session._flow_snapshot(this)
    else
      _h.fail("missing case, seed 0x52f10a7")
    end

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    try
      _h.assert_eq[USize](_packets, pending_packets)
      _h.assert_eq[USize](_admitted + (9 * _packets), pending_bytes)
      (let credit, let length, _) = _cases(_case)?
      let expected: U32 = if length > 32768 then 0
        else length.min(credit.usize()).u32() end
      _h.assert_eq[U32](credit - expected, remote_window,
        "credit, seed 0x52f10a7 case " + _case.string())
      _h.assert_eq[Bool]((length <= 32768) and
        (length > credit.usize()), blocked)
      _h.assert_false(terminated)
      match _session
      | let session: SshSession tag => session.disconnect()
      end
      _session = None
      _case = _case + 1
      _run_case()
    else
      _h.fail("missing snapshot case, seed 0x52f10a7")
    end

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be _flow_barrier() => None

class \nodoc\ iso _TestFlowGeneratedRetry is UnitTest
  fun name(): String => "ssh_transport/flow_generated_retry"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)
    _FlowGeneratedRetryNotify(h)

actor \nodoc\ _FlowGeneratedRetryNotify is
  (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _cases: Array[(USize, U32, U32, U32)] =
    Array[(USize, U32, U32, U32)]
  var _case: USize = 0
  var _phase: USize = 0
  var _barrier_stage: USize = 0
  var _hints: USize = 0
  var _admitted: USize = 0
  var _packets: USize = 0
  var _results: USize = 0
  var _data: Array[U8] val = recover val Array[U8] end
  var _sent: Array[U8] val = recover val Array[U8] end
  var _session: (SshSession tag | None) = None

  new create(h: TestHelper) =>
    _h = h
    _cases.push((400, 100, 50, 20))
    let rng = Rand(0x31b7ca)
    for i in Range[USize](0, 24) do
      let length: USize = 300 + (rng.u32() % 1701).usize()
      let first: U32 = 1 + (rng.u32() % (length.u32() / 3))
      let remaining = length.u32() - first
      let grant1: U32 = 1 + (rng.u32() % (remaining / 4))
      let grant2: U32 = 1 + (rng.u32() % (remaining / 4))
      _cases.push((length, first, grant1, grant2))
    end
    _run_case()

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  fun ref _run_case() =>
    try
      (let length, let first, _, _) = _cases(_case)?
      let case_id = _case
      _data = recover val
        let bytes = Array[U8].create(length)
        for i in Range[USize](0, length) do
          bytes.push(((i.u64() * 97) xor (i.u64() >> 2) xor
            (case_id.u64() * 191)).u8())
        end
        bytes
      end
      _sent = _data
      _admitted = 0
      _packets = 0
      _results = 0
      _hints = 0
      _phase = 0
      _barrier_stage = 0
      let session = SshSession._flow_test(this, this, first, 256, 40)
      _session = session
      session.channel_send(0, _sent)
    else
      _h.complete(true)
    end

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      if reader.read_byte()? != SshChannelMsgTypes.channel_data() then
        return
      end
      _h.assert_eq[U32](7, reader.read_u32()?)
      let bytes = reader.read_string()?
      _h.assert_true((bytes.size() > 0) and (bytes.size() <= 256))
      for i in Range[USize](0, bytes.size()) do
        if bytes(i)? != _data(_admitted + i)? then
          _h.fail("retry prefix, seed 0x31b7ca case " + _case.string())
          return
        end
      end
      _admitted = _admitted + bytes.size()
      _packets = _packets + 1
    else
      _h.fail("retry packet or expected data, seed 0x31b7ca case " +
        _case.string())
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    try
      (let length, let first, let grant1, let grant2) = _cases(_case)?
      _results = _results + 1
      _h.assert_eq[U32](0, channel_id)
      _h.assert_true(data is _sent)
      let expected: USize = if _phase == 0 then first.usize()
        elseif _phase == 1 then (grant1 + grant2).usize()
        else length - first.usize() - grant1.usize() - grant2.usize() end
      _h.assert_eq[USize](expected, accepted,
        "retry accepted, seed 0x31b7ca case " + _case.string())
      _h.assert_eq[USize](if _phase == 0 then first.usize()
        elseif _phase == 1 then first.usize() + grant1.usize() +
          grant2.usize()
        else length end, _admitted)
      if _phase < 2 then
        _h.assert_true(outcome is SshSendWindowBlocked)
      else
        _h.assert_true(outcome is SshSendComplete)
      end
      if _phase == 0 then
        _phase = 1
        session._flow_dispatch_grants(recover val [as U32: 0] end, this)
      elseif _phase == 1 then
        _phase = 2
        session._flow_dispatch_grants(
          recover val [as U32: 0] end, this)
      else
        _h.assert_eq[USize](3, _results)
        session._flow_snapshot(this)
      end
    else
      _h.fail("retry missing case, seed 0x31b7ca")
    end

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) =>
    _h.assert_eq[U32](0, channel_id)
    match _session
    | let current: SshSession tag => _h.assert_true(session is current)
    | None => _h.fail("window hint without active session")
    end
    _hints = _hints + 1
    _h.assert_true(_hints <= 2,
      "duplicate hint, seed 0x31b7ca case " + _case.string())

  be _flow_barrier() =>
    match _session
    | let session: SshSession tag =>
      try
        (let length, _, let grant1, let grant2) = _cases(_case)?
        if _barrier_stage == 0 then
          _h.assert_eq[USize](0, _hints)
          _barrier_stage = 1
          session._flow_dispatch_grants(
            recover val [as U32: grant1; grant2] end, this)
        elseif _barrier_stage == 1 then
          _h.assert_eq[USize](1, _hints)
          _barrier_stage = 2
          _sent = _data.trim(_admitted)
          session.channel_send(0, _sent)
        elseif _barrier_stage == 2 then
          _h.assert_eq[USize](1, _hints)
          _barrier_stage = 3
          let final_grant = (length - _admitted).u32()
          session._flow_dispatch_grants(
            recover val [as U32: final_grant] end, this)
        else
          _h.assert_eq[USize](2, _hints)
          _sent = _data.trim(_admitted)
          session.channel_send(0, _sent)
        end
      else
        _h.fail("retry barrier case missing")
      end
    end

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    _h.assert_eq[USize](_packets, pending_packets)
    _h.assert_eq[USize](_admitted + (9 * _packets), pending_bytes)
    _h.assert_eq[U32](0, remote_window)
    _h.assert_false(blocked)
    _h.assert_false(terminated)
    match _session
    | let session: SshSession tag => session.disconnect()
    end
    _session = None
    _case = _case + 1
    _run_case()
