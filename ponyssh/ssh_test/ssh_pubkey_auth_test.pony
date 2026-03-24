use "encode/base64"
use "pony_test"
use "lori"
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
    let server_config = SshServerConfig(server_pem, "127.0.0.1", "19828")

    let server_notify = _PubkeyServerNotify(h)
    let listen_auth = TCPListenAuth(h.env.root)
    let listener = SshListener(listen_auth, server_config, server_notify)
    server_notify.set_listener(listener)

    // Client authenticates with the ponyssh-testing private key
    let client_key = _TestPubkeyPem()
    let client_config = SshClientConfig("127.0.0.1", "19828",
      "testuser",
      recover val [as SshAuthMethod val: SshPublicKeyAuth(client_key)] end)
    let connect_auth = TCPConnectAuth(h.env.root)
    SshConnector.connect(connect_auth, client_config,
      _PubkeyClientNotify(h))


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

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) => None

  be ssh_disconnected(session: SshSession tag) =>
    _h.complete(true)


actor _PubkeyServerNotify is SshServerNotify
  let _h: TestHelper
  let _authorized_key: Array[U8] val = _TestPubkeyAuthorized()
  var _listener: (SshListener tag | None) = None

  new create(h: TestHelper) =>
    _h = h

  be set_listener(listener: SshListener tag) =>
    _listener = listener

  be ssh_session_started(session: SshSession tag) => None

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    match request.method_data
    | let pk: SshAuthPublicKeyData val =>
      // Check key matches authorized key
      if not SshMac.verify(pk.public_key, _authorized_key) then
        _h.fail("Server received unknown public key")
        let remaining = recover val
          let a = Array[String val]
          a.push("publickey")
          a
        end
        session.auth_reject(remaining)
        return
      end
      match pk.signature
      | None =>
        // Query — accept this key
        session.auth_pk_ok(pk.algorithm, pk.public_key)
      | let _: Array[U8] val =>
        // Actual auth with signature — accept
        session.auth_accept()
      end
    else
      let remaining = recover val
        let a = Array[String val]
        a.push("publickey")
        a
      end
      session.auth_reject(remaining)
    end

  be ssh_session_ready(session: SshSession tag) => None

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  =>
    if want_reply then session.accept_request(channel_id) end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    if want_reply then session.accept_request(channel_id) end

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
  =>
    None

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  =>
    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    if String.from_array(data) == "closeme" then
      session.disconnect()
      match _listener
      | let l: SshListener tag => l.dispose()
      end
    end

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("Server error: " + err.string())
    _h.complete(true)

  be ssh_disconnected(session: SshSession tag) => None
