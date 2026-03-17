use "pony_test"
use "lori"
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
    let server_config = SshServerConfig(pem, "127.0.0.1", "19827")

    let tracker = _IntegrationTracker(h)

    let server_notify = _IntegrationServerNotify(tracker)
    let listen_auth = TCPListenAuth(h.env.root)
    let listener = SshListener(listen_auth, server_config, server_notify)

    let client_config = SshClientConfig("127.0.0.1", "19827",
      "testuser",
      recover val [as SshAuthMethod val: SshNoneAuth] end)
    let client_notify = _IntegrationClientNotify(tracker)
    let connect_auth = TCPConnectAuth(h.env.root)
    SshConnector.connect(connect_auth, client_config, client_notify)


actor _IntegrationTracker
  """Tracks whether both client and server reached ready state."""
  let _h: TestHelper
  var _client_ready: Bool = false
  var _server_ready: Bool = false

  new create(h: TestHelper) =>
    _h = h

  be client_ready() =>
    _client_ready = true
    _check_complete()

  be server_ready() =>
    _server_ready = true
    _check_complete()

  be fail(msg: String) =>
    _h.fail(msg)
    _h.complete(true)

  fun ref _check_complete() =>
    if _client_ready and _server_ready then
      _h.complete(true)
    end


actor _IntegrationClientNotify is SshClientNotify
  let _tracker: _IntegrationTracker tag

  new create(tracker: _IntegrationTracker tag) =>
    _tracker = tracker

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    _tracker.client_ready()

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _tracker.fail("Client auth failed: " + err.string())

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) => None
  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _tracker.fail("Client error: " + err.string())

  be ssh_disconnected(session: SshSession tag) => None


actor _IntegrationServerNotify is SshServerNotify
  let _tracker: _IntegrationTracker tag

  new create(tracker: _IntegrationTracker tag) =>
    _tracker = tracker

  be ssh_session_started(session: SshSession tag) => None

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    session.auth_accept()

  be ssh_session_ready(session: SshSession tag) =>
    _tracker.server_ready()

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val) => None

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _tracker.fail("Server error: " + err.string())

  be ssh_disconnected(session: SshSession tag) => None
