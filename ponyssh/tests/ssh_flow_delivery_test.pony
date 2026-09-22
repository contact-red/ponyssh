use "pony_test"
use "net"
use "collections"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

primitive \nodoc\ _FlowDeliverySize
  fun apply(): USize => 1024 + 257

class \nodoc\ iso _TestIntegrationFlowDelivery is UnitTest
  fun name(): String => "integration/flow_delivery"

  fun apply(h: TestHelper) =>
    h.long_test(20_000_000_000)
    let config = match MakeSshServerConfig(_TestEd25519Pem(),
      "127.0.0.1", "19831" where channel_window' = 1024)
    | let created: SshServerConfig val => created
    | let err: SshServerConfigError => h.fail(err.string()); return
    end
    let client_config = SshClientConfig("127.0.0.1", "19831",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let client = _FlowDeliveryClientNotify(h)
    let server = _FlowDeliveryServerNotify(TCPConnectAuth(h.env.root),
      client_config, client)
    h.dispose_when_done(SshListener(TCPListenAuth(h.env.root), config,
      server))

actor \nodoc\ _FlowDeliveryClientNotify is SshClientNotify
  let _h: TestHelper
  let _source: Array[U8] val = recover val
    let bytes = Array[U8].create(_FlowDeliverySize())
    for i in Range[USize](0, _FlowDeliverySize()) do
      bytes.push((i % 251).u8())
    end
    bytes
  end
  var _offset: USize = 0
  var _pending: (Array[U8] val | None) = None
  var _blocked: Bool = false
  var _saw_blocked: Bool = false
  var _saw_hint: Bool = false
  var _channel_id: U32 = 0
  var _done: Bool = false
  var _acknowledged: Bool = false
  var _server_result: (Bool | None) = None
  var _client_session: (SshSession tag | None) = None

  new create(h: TestHelper) => _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    _client_session = session
    session.open_channel("session")

  be _flow_server_send_result(valid: Bool) =>
    _server_result = valid
    _try_complete()

  be _flow_server_failure(reason: String val) =>
    _fail(reason)

  fun ref _fail(reason: String val) =>
    if _done then return end
    _done = true
    _h.fail(reason)
    _h.complete(true)
    match _client_session
    | let session: SshSession tag => session.disconnect()
    end

  fun ref _try_complete() =>
    if _done then return end
    match _server_result
    | let valid: Bool =>
      if not valid then
        _fail("server acknowledgment was not fully admitted")
        return
      elseif not _acknowledged then
        return
      end
      _done = true
      _h.complete(true)
      match _client_session
      | let session: SshSession tag => session.disconnect()
      end
    end

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _fail("flow delivery auth failed: " + err.string())

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    _channel_id = channel_id
    _send_next(session)

  be ssh_channel_request_result(session: SshSession tag, channel_id: U32,
    accepted: Bool) => None

  fun ref _send_next(session: SshSession tag) =>
    if _offset >= _source.size() then return end
    let end_offset = (_offset + 32768).min(_source.size())
    let data = _source.trim(_offset, end_offset)
    _pending = data
    session.channel_send(_channel_id, data)

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    match _pending
    | let expected: Array[U8] val => _h.assert_true(data is expected)
    | None => _h.fail("send result without pending data")
    end
    _h.assert_true(accepted <= data.size())
    _offset = _offset + accepted
    match outcome
    | SshSendComplete =>
      _pending = None
      _send_next(session)
    | SshSendWindowBlocked =>
      _pending = data.trim(accepted)
      _blocked = true
      _saw_blocked = true
    else
      _fail("flow delivery send did not complete")
    end

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32)
  =>
    if not _blocked then
      _fail("window hint without blocked send")
      return
    end
    _blocked = false
    _saw_hint = true
    match _pending
    | let data: Array[U8] val => session.channel_send(channel_id, data)
    | None => _fail("window hint without pending data")
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    _h.assert_eq[String]("ok", String.from_array(data))
    _h.assert_eq[USize](_FlowDeliverySize(), _offset)
    _h.assert_true(_pending is None)
    _h.assert_true(_saw_blocked)
    _h.assert_true(_saw_hint)
    _acknowledged = true
    _try_complete()

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val)
  =>
    _fail("flow delivery channel error: " + err.string())

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _fail("flow delivery client error: " + err.string())

  be ssh_disconnected(session: SshSession tag) =>
    _fail("flow delivery disconnected before acknowledgment")

actor \nodoc\ _FlowDeliveryServerNotify is SshServerNotify
  let _connect_auth: TCPConnectAuth
  let _client_config: SshClientConfig val
  let _client_notify: _FlowDeliveryClientNotify tag
  var _listener: (DisposableActor tag | None) = None
  var _received: USize = 0

  new create(connect_auth: TCPConnectAuth,
    client_config: SshClientConfig val,
    client_notify: _FlowDeliveryClientNotify tag)
  =>
    _connect_auth = connect_auth
    _client_config = client_config
    _client_notify = client_notify

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_listener_started(listener: DisposableActor tag) =>
    _listener = listener
    SshConnector.connect(_connect_auth, _client_config, _client_notify)

  be ssh_listener_failed(listener: DisposableActor tag) =>
    _client_notify._flow_server_failure(
      "flow delivery listener failed to bind port 19831")

  be ssh_session_started(session: SshSession tag) =>
    match _listener
    | let listener: DisposableActor tag =>
      listener.dispose()
      _listener = None
    end

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    try
      for i in Range[USize](0, data.size()) do
        if data(i)? != ((_received + i) % 251).u8() then
          _client_notify._flow_server_failure(
            "flow delivery byte mismatch at " + (_received + i).string())
          session.disconnect()
          return
        end
      end
    else
      _client_notify._flow_server_failure("invalid flow delivery data")
      session.disconnect()
      return
    end
    _received = _received + data.size()
    if _received > _FlowDeliverySize() then
      _client_notify._flow_server_failure("flow delivery exceeded source size")
      session.disconnect()
      return
    end
    if _received == _FlowDeliverySize() then
      session.channel_send(channel_id, "ok".array())
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome)
  =>
    _client_notify._flow_server_send_result(
      (accepted == 2) and (outcome is SshSendComplete))

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) =>
    _client_notify._flow_server_failure("unexpected server window hint")

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _client_notify._flow_server_failure(
      "flow delivery server error: " + err.string())
