use "pony_test"
use "lori"
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
      try SshServerConfig(pem, "127.0.0.1", "19829")?
      else h.fail("invalid host key"); return
      end

    let server_notify = _RejectHostKeyServerNotify(h)
    let listen_auth = TCPListenAuth(h.env.root)
    let listener = SshListener(listen_auth, server_config, server_notify)
    server_notify.set_listener(listener)

    let client_config = SshClientConfig("127.0.0.1", "19829",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let connect_auth = TCPConnectAuth(h.env.root)
    SshConnector.connect(connect_auth, client_config,
      _RejectHostKeyClientNotify(h))


actor _RejectHostKeyClientNotify is SshClientNotify
  let _h: TestHelper

  new create(h: TestHelper) =>
    _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
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
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) => None

  be ssh_disconnected(session: SshSession tag) =>
    // Expected: rejection tore the connection down before authentication.
    _h.complete(true)


actor _RejectHostKeyServerNotify is SshServerNotify
  let _h: TestHelper
  var _listener: (SshListener tag | None) = None

  new create(h: TestHelper) =>
    _h = h

  be set_listener(listener: SshListener tag) =>
    _listener = listener

  // Accept any credential. This is only ever consulted if the client proceeded
  // to auth — which means the host-key gate failed. Accepting makes the
  // client's ssh_ready fire so the test fails loudly.
  fun validate_password(username: String val, password: String val): Bool =>
    true

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => true

  be ssh_session_started(session: SshSession tag) =>
    // Only one connection is expected; stop listening so the runtime can
    // quiesce regardless of how the rejected handshake unwinds.
    match _listener
    | let l: SshListener tag =>
      l.dispose()
      _listener = None
    end
