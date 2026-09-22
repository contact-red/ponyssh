use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class iso _TestIntegrationHandshake is UnitTest
  fun name(): String => "integration/handshake"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)  // 10 second timeout

    let pem = _TestEd25519Pem()
    let server_config =
      match MakeSshServerConfig(pem, "127.0.0.1", "19827")
      | let config: SshServerConfig val => config
      | let err: SshServerConfigError => h.fail(err.string()); return
      end

    let client_config = SshClientConfig("127.0.0.1", "19827",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let server_notify = _IntegrationServerNotify(h, TCPConnectAuth(h.env.root),
      client_config, _IntegrationClientNotify(h))
    let listen_auth = TCPListenAuth(h.env.root)
    h.dispose_when_done(SshListener(listen_auth, server_config, server_notify))


actor _IntegrationClientNotify is SshClientNotify
  let _h: TestHelper

  new create(h: TestHelper) =>
    _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    session.open_channel("session")

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("Client auth failed: " + err.string())
    _h.complete(true)

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    let closeme: Array[U8] val = recover val
      let a = Array[U8]
      for ch in "closeme".values() do a.push(ch) end
      a
    end
    session.channel_send(channel_id, closeme)

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) =>
    _h.assert_eq[USize](data.size(), accepted)
    _h.assert_true(outcome is SshSendComplete)
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("client error: " + err.string())
    _h.complete(true)

  be ssh_disconnected(session: SshSession tag) =>
    _h.complete(true)


actor _IntegrationServerNotify is SshServerNotify
  let _h: TestHelper
  let _connect_auth: TCPConnectAuth
  let _client_config: SshClientConfig val
  let _client_notify: SshClientNotify tag
  var _listener: (DisposableActor tag | None) = None

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None

  new create(h: TestHelper, connect_auth: TCPConnectAuth,
    client_config: SshClientConfig val, client_notify: SshClientNotify tag)
  =>
    _h = h
    _connect_auth = connect_auth
    _client_config = client_config
    _client_notify = client_notify

  be ssh_listener_started(listener: DisposableActor tag) =>
    _listener = listener
    SshConnector.connect(_connect_auth, _client_config, _client_notify)

  be ssh_listener_failed(listener: DisposableActor tag) =>
    _h.fail("listener failed to bind")
    _h.complete(true)

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_session_started(session: SshSession tag) =>
    // Only one connection is expected; stop accepting once it arrives.
    match _listener
    | let l: DisposableActor tag =>
      l.dispose()
      _listener = None
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    if String.from_array(data) == "closeme" then
      session.disconnect()
      match _listener
      | let l: DisposableActor tag => l.dispose()
      end
    end

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("Server error: " + err.string())
    _h.complete(true)
