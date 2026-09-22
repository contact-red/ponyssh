use "encode/base64"
use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

primitive _TestPubkeyPem
  fun apply(): Array[U8] val =>
    """Ed25519 private key in PEM format for pubkey auth testing."""
    (recover val
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIJlvJ745dd3IRo8vQAqiJHYOLNHQU6npurolza4mv9Tb\n" +
      "-----END PRIVATE KEY-----\n"
    end).array()

primitive _TestPubkeyAuthorized
  fun apply(): Array[U8] val =>
    """SSH public key blob for the above PEM key."""
    try
      Base64.decode[Array[U8] iso](
        "AAAAC3NzaC1lZDI1NTE5AAAAIOM+pYkppICJgHEpxei+6CBS1UYznSVH/qojON+nh4DP")?
    else
      recover val Array[U8] end
    end

class iso _TestIntegrationPubkeyAuth is UnitTest
  fun name(): String => "integration/pubkey_auth"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)

    let server_pem = _TestEd25519Pem()  // host key
    let server_config =
      match MakeSshServerConfig(server_pem, "127.0.0.1", "19828")
      | let config: SshServerConfig val => config
      | let err: SshServerConfigError => h.fail(err.string()); return
      end

    // Client authenticates with the ponyssh-testing private key
    let client_key = _TestPubkeyPem()
    let client_config = SshClientConfig("127.0.0.1", "19828",
      "testuser",
      recover val [as SshAuthMethod val: SshPublicKeyAuth(client_key)] end)
    let server_notify = _PubkeyServerNotify(h, TCPConnectAuth(h.env.root),
      client_config, _PubkeyClientNotify(h))
    let listen_auth = TCPListenAuth(h.env.root)
    h.dispose_when_done(SshListener(listen_auth, server_config, server_notify))


actor _PubkeyClientNotify is SshClientNotify
  let _h: TestHelper

  new create(h: TestHelper) =>
    _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    // Auth succeeded — send closeme to clean up
    session.open_channel("session")

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("Client pubkey auth failed: " + err.string())
    _h.complete(true)

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    session.channel_send(channel_id, "closeme".array())

  be ssh_channel_request_result(session: SshSession tag, channel_id: U32,
    accepted: Bool) => None

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


actor _PubkeyServerNotify is SshServerNotify
  let _h: TestHelper
  let _authorized_key: Array[U8] val = _TestPubkeyAuthorized()
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
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool
  =>
    pk.matches(_authorized_key)

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
