use "pony_test"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_error"

class \nodoc\ iso _TestFlowPeerPacketRejection is UnitTest
  fun name(): String => "ssh_transport/peer_packet_rejection"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)
    _FlowPeerPacketNotify(h)

actor \nodoc\ _FlowPeerPacketNotify is (SshServerNotify & _SshFlowObserver)
  let _h: TestHelper
  let _session: SshSession tag
  var _barriers: USize = 0
  var _failures: USize = 0
  var _closes: USize = 0
  var _errors: USize = 0

  new create(h: TestHelper) =>
    _h = h
    _session = SshSession._flow_test(this, this, 0, 256, 10, false)
    _session._flow_dispatch_peer_open(128, this)
    _session._flow_dispatch_peer_confirmation(128, this)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    _h.fail("unsupported incoming channel reached the application")

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val)
  =>
    _h.assert_eq[U32](0, channel_id)
    match err
    | let unsupported: SshChannelUnsupportedPacketSize =>
      _h.assert_eq[U32](128, unsupported.advertised)
      _errors = _errors + 1
    else _h.fail("wrong outgoing rejection error")
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None

  be _flow_admitted(payload: Array[U8] val) =>
    try
      let reader = SshWireReader(payload)
      match reader.read_byte()?
      | 92 =>
        _h.assert_eq[U32](9, reader.read_u32()?)
        _h.assert_eq[U32](1, reader.read_u32()?)
        _failures = _failures + 1
      | 97 =>
        _h.assert_eq[U32](7, reader.read_u32()?)
        _closes = _closes + 1
      else _h.fail("unexpected packet during peer size rejection")
      end
    else
      _h.fail("invalid peer size rejection packet")
    end

  be _flow_barrier() =>
    _barriers = _barriers + 1
    if _barriers == 2 then
      _h.assert_eq[USize](1, _failures)
      _h.assert_eq[USize](1, _closes)
      _h.assert_eq[USize](1, _errors)
      _session.disconnect()
      _h.complete(true)
    end

  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool) => None
