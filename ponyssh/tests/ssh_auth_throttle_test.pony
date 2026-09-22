use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class iso _TestAuthAttemptsCapped is UnitTest
  """
  A server session must stop answering authentication attempts once the cap is
  reached, rather than letting one connection carry unlimited guesses.

  Without a cap an unauthenticated peer pipelines USERAUTH_REQUESTs down a
  single TCP connection at line rate: every rejection only sends USERAUTH_FAILURE
  and leaves the session in Auth, ready for the next guess. There is no lockout
  and no connection churn for an operator or fail2ban to notice.

  The client here is configured with more wrong passwords than the cap allows.
  Each rejection advances it to the next method, so it would send all of them.
  The server must disconnect after the cap, which the consumer observes as the
  auth callback being invoked exactly _max_auth_attempts times and no more.
  """
  fun name(): String => "integration/auth_attempts_capped"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)  // 10 second timeout

    let pem = _TestEd25519Pem()
    let server_config =
      try SshServerConfig(pem, "127.0.0.1", "19831")?
      else h.fail("invalid host key"); return
      end

    // Ten wrong passwords against a cap of six. A client that gets to try all
    // ten is a server that never stopped it.
    let methods: Array[SshAuthMethod val] val = recover val
      let a = Array[SshAuthMethod val]
      var i: USize = 0
      while i < 10 do
        a.push(SshPasswordAuth("wrong-" + i.string()))
        i = i + 1
      end
      a
    end

    let client_config = SshClientConfig("127.0.0.1", "19831", "testuser",
      methods)
    let server_notify = _ThrottleServerNotify(h, TCPConnectAuth(h.env.root),
      client_config)
    let listen_auth = TCPListenAuth(h.env.root)
    h.dispose_when_done(SshListener(listen_auth, server_config, server_notify))


actor _ThrottleServerNotify is SshServerNotify
  """
  Rejects every password and counts how many attempts the session let through.
  The count is the assertion: it must stop at the session's cap.
  """
  let _h: TestHelper
  let _connect_auth: TCPConnectAuth
  let _client_config: SshClientConfig val
  var _listener: (DisposableActor tag | None) = None
  var _attempts: USize = 0

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None

  new create(h: TestHelper, connect_auth: TCPConnectAuth,
    client_config: SshClientConfig val)
  =>
    _h = h
    _connect_auth = connect_auth
    _client_config = client_config

  be ssh_listener_started(listener: DisposableActor tag) =>
    _listener = listener
    SshConnector.connect(_connect_auth, _client_config,
      _ThrottleClientNotify(_h, this))

  be ssh_listener_failed(listener: DisposableActor tag) =>
    _h.fail("listener failed to bind")
    _h.complete(true)

  be report_to(client: _ThrottleClientNotify tag) =>
    client.attempts_seen(_attempts)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    _attempts = _attempts + 1
    session.auth_reject(["password"])

  be ssh_session_started(session: SshSession tag) =>
    match _listener
    | let l: DisposableActor tag =>
      l.dispose()
      _listener = None
    end

  be ssh_error(session: SshSession tag, err: SshTransportError val) => None


actor _ThrottleClientNotify is SshClientNotify
  """
  Drives the guesses and, once the server has torn the session down, asks the
  server consumer how many attempts it was asked to judge.
  """
  let _h: TestHelper
  let _server: _ThrottleServerNotify tag
  var _reported: Bool = false

  new create(h: TestHelper, server: _ThrottleServerNotify tag) =>
    _h = h
    _server = server

  be attempts_seen(count: USize) =>
    // Six is _max_auth_attempts in SshSession: OpenSSH's MaxAuthTries default.
    _h.assert_eq[USize](6, count,
      "the session let the peer make " + count.string()
        + " authentication attempts on one connection")
    _h.complete(true)

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    _h.fail("authentication succeeded with a wrong password")
    _h.complete(true)

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    // Reached only if the client exhausts its own method list first, which
    // means the server never cut it off. Let the count assertion report it.
    _ask_server()

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
    _h.fail("client error: " + err.string())
    _h.complete(true)

  be ssh_disconnected(session: SshSession tag) =>
    _ask_server()

  fun ref _ask_server() =>
    if _reported then return end
    _reported = true
    _server.report_to(this)
