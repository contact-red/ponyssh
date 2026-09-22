use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class iso _TestIntegrationHostKeyReject is UnitTest
  """
  When the client consumer rejects the server's host key, the session must tear
  down before authentication starts — the client must never send credentials to
  an unapproved host. The server auto-accepts auth, so if the client wrongly
  proceeded, ssh_ready would fire and fail the test.
  """
  fun name(): String => "integration/hostkey_reject"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)

    let pem = _TestEd25519Pem()
    let server_config =
      match MakeSshServerConfig(pem, "127.0.0.1", "19829")
      | let config: SshServerConfig val => config
      | let err: SshServerConfigError => h.fail(err.string()); return
      end

    let client_config = SshClientConfig("127.0.0.1", "19829",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let server_notify = _RejectHostKeyServerNotify(h,
      TCPConnectAuth(h.env.root), client_config, _RejectHostKeyClientNotify(h))
    let listen_auth = TCPListenAuth(h.env.root)
    h.dispose_when_done(SshListener(listen_auth, server_config, server_notify))


actor _RejectHostKeyClientNotify is SshClientNotify
  let _h: TestHelper
  var _rejected: Bool = false

  new create(h: TestHelper) =>
    _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    _rejected = true
    session.reject_host_key()

  be ssh_ready(session: SshSession tag) =>
    _h.fail("ssh_ready fired despite host-key rejection; auth must not start")
    _h.complete(true)

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("authentication started despite host-key rejection: " + err.string())
    _h.complete(true)

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) => None
  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    // Rejecting the host key is reported as a key-exchange failure. Any other
    // error means the session ended for a reason this test did not cause.
    match err
    | let _: SshKexFailed => None
    else
      _h.fail("client error: " + err.string())
      _h.complete(true)
    end

  be ssh_disconnected(session: SshSession tag) =>
    // Expected: rejection tore the connection down before authentication. A
    // key exchange that failed before the host key was offered also ends
    // here, so the test passes only if the rejection is what ended it.
    _h.assert_true(_rejected,
      "the session ended before the host key was offered for verification")
    _h.complete(true)


actor _RejectHostKeyServerNotify is SshServerNotify
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

  // Accept any credential. This is only ever consulted if the client proceeded
  // to auth — which means the host-key gate failed. Accepting makes the
  // client's ssh_ready fire so the test fails loudly.
  fun validate_password(username: String val, password: String val): Bool =>
    true

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => true

  be ssh_session_started(session: SshSession tag) =>
    // Only one connection is expected; stop accepting once it arrives.
    match _listener
    | let l: DisposableActor tag =>
      l.dispose()
      _listener = None
    end

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("server error: " + err.string())
    _h.complete(true)
