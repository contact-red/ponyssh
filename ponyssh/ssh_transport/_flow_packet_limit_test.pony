use "pony_test"
use "net"
use "../ssh_auth"
use "../ssh_crypto"
use "../ssh_connection"
use "../ssh_error"

class \nodoc\ iso _TestFlowPacketLimit is UnitTest
  fun name(): String => "ssh_transport/flow_packet_limit"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)
    let config = match MakeSshServerConfig(_FlowLimitPem(),
      "127.0.0.1", "19832")
    | let created: SshServerConfig val => created
    | let err: SshServerConfigError => h.fail(err.string()); return
    end
    let client = _FlowLimitClient(h, TCPConnectAuth(h.env.root))
    h.dispose_when_done(_FlowLimitListener(TCPListenAuth(h.env.root),
      config, _FlowLimitServer(h), client, h))

primitive \nodoc\ _FlowLimitPem
  fun apply(): Array[U8] val =>
    (recover val
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIL5WXOw5lzhPk0Y4iNRzTuq+lGgyONPJrY0XOsqPtuAD\n" +
      "-----END PRIVATE KEY-----\n"
    end).array()

actor \nodoc\ _FlowLimitListener is TCPListenerActor
  var _tcp_listener: TCPListener = TCPListener.none()
  let _config: SshServerConfig val
  let _notify: SshServerNotify tag
  let _client: _FlowLimitClient tag
  let _h: TestHelper
  let _auth: TCPListenAuth

  new create(auth: TCPListenAuth, config: SshServerConfig val,
    notify: SshServerNotify tag, client: _FlowLimitClient tag,
    h: TestHelper)
  =>
    _auth = auth
    _config = config
    _notify = notify
    _client = client
    _h = h
    _tcp_listener = TCPListener(auth, config.listen_host, config.listen_port,
      this)

  fun ref _listener(): TCPListener => _tcp_listener

  fun ref _on_accept(fd: U32): SshServerTcpBridge =>
    let session = SshSession.create_server(_config, _notify)
    let bridge = SshServerTcpBridge(TCPServerAuth(_auth), fd, session)
    session.set_server_bridge(bridge)
    bridge

  fun ref _on_listening() => _client.start()
  fun ref _on_listen_failure() =>
    _h.fail("packet-limit listener failed to bind port 19832")
    _h.complete(true)
  fun ref _on_closed() => None

actor \nodoc\ _FlowLimitClient is SshClientNotify
  let _h: TestHelper
  let _auth: TCPConnectAuth
  let _data: Array[U8] val = recover val Array[U8].init(91, 600) end

  new create(h: TestHelper, auth: TCPConnectAuth) =>
    _h = h
    _auth = auth

  be start() =>
    let config = SshClientConfig("127.0.0.1", "19832", "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    SshSession.create_client(_auth, config, this)

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    session.open_channel("session")

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("packet-limit auth failed: " + err.string())
    _h.complete(true)

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    session._flow_stop_after_next_packet(channel_id)
    session.channel_send(channel_id, _data)

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _h.assert_true(data is _data)
    _h.assert_eq[USize](256, accepted)
    _h.assert_true(outcome is SshSendClosed)
    _h.complete(true)

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => _h.fail("unexpected window hint")

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) =>
    _h.fail("packet-limit channel error: " + err.string())
    _h.complete(true)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    if not (err is SshRekeyUnsupported) then
      _h.fail("unexpected packet-limit error: " + err.string())
      _h.complete(true)
    end
  be ssh_disconnected(session: SshSession tag) => None

actor \nodoc\ _FlowLimitServer is SshServerNotify
  let _h: TestHelper

  new create(h: TestHelper) => _h = h

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"
  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("packet-limit server error: " + err.string())
    _h.complete(true)
