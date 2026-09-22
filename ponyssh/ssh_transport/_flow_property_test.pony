use "pony_test"
use "collections"
use "../ssh_auth"
use "../ssh_connection"

class \nodoc\ iso _TestFlowPrefixConservation is UnitTest
  fun name(): String => "ssh_transport/flow_prefix_conservation"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)
    _FlowPropertyNotify(h)

actor \nodoc\ _FlowPropertyNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _cases: Array[(U32, USize, U32, USize)] val =
    [ (0, 1, 256, 256)
      (1, 1, 256, 256)
      (1, 257, 256, 256)
      (255, 256, 257, 257)
      (256, 257, 256, 256)
      (257, 257, 257, 257)
      (511, 1024, 512, 512)
      (512, 512, 512, 512)
      (700, 4096, 1024, 1024)
      (1024, 700, 4096, 4096)
      (32767, 32768, 32767, 32767)
      (32768, 32768, 32768, 32768)
      (32768, 32768, 32769, 32768)
      (32768, 0, U32.max_value(), 32768) ]
  var _case: USize = 0
  var _data: Array[U8] val = recover val Array[U8] end
  var _admitted: USize = 0
  var _packet_count: USize = 0
  var _session: (SshSession tag | None) = None
  var _seen_complete: Bool = false
  var _seen_blocked: Bool = false
  var _seen_middle: Bool = false
  var _seen_high_clamp: Bool = false

  new create(h: TestHelper) =>
    _h = h
    _run_case()

  fun validate_password(username: String val, password: String val): Bool =>
    false
  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  fun ref _run_case() =>
    try
      (let credit, let length, let advertised, let limit) = _cases(_case)?
      _data = recover val
        let bytes = Array[U8].create(length)
        for i in Range[USize](0, length) do bytes.push(i.u8()) end
        bytes
      end
      _admitted = 0
      _packet_count = 0
      if advertised > 32768 then _seen_high_clamp = true
      else _seen_middle = true end
      let session = SshSession._flow_test(this, this, credit,
        advertised, 200)
      _session = session
      session.channel_send(0, _data)
    else
      _h.assert_true(_seen_complete)
      _h.assert_true(_seen_blocked)
      _h.assert_true(_seen_middle)
      _h.assert_true(_seen_high_clamp)
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
      (_, _, _, let limit) = _cases(_case)?
      _h.assert_true((bytes.size() > 0) and (bytes.size() <= limit))
      for i in Range[USize](0, bytes.size()) do
        if bytes(i)? != _data(_admitted + i)? then
          _h.fail("admitted prefix differs in case " + _case.string())
          return
        end
      end
      _admitted = _admitted + bytes.size()
      _packet_count = _packet_count + 1
    else
      _h.fail("invalid admitted packet in case " + _case.string())
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    try
      (let credit, let length, _, _) = _cases(_case)?
      _h.assert_true(data is _data)
      _h.assert_eq[USize](length.min(credit.usize()), accepted)
      _h.assert_eq[USize](accepted, _admitted)
      if length <= credit.usize() then
        _h.assert_true(outcome is SshSendComplete)
        _seen_complete = true
      else
        _h.assert_true(outcome is SshSendWindowBlocked)
        _seen_blocked = true
      end
      if accepted == 0 then
        _h.assert_eq[USize](0, _packet_count)
      else
        _h.assert_true(_packet_count > 0)
      end
      session._flow_snapshot(this)
    else
      _h.fail("missing property case")
      _h.complete(true)
    end

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
  =>
    try
      (let credit, let length, _, _) = _cases(_case)?
      _h.assert_eq[U32](credit - length.min(credit.usize()).u32(),
        remote_window)
      _h.assert_eq[Bool](length > credit.usize(), blocked)
      _h.assert_false(terminated)
      match _session
      | let session: SshSession tag => session.disconnect()
      end
      _session = None
      _case = _case + 1
      _run_case()
    else
      _h.fail("missing property snapshot case")
      _h.complete(true)
    end

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected property window hint")

  be _flow_barrier() => None
