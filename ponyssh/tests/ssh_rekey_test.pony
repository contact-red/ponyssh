use "pony_test"
use "lori"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class iso _TestIntegrationRekey is UnitTest
  """
  After a full handshake the client triggers a key re-exchange, then exchanges
  application data across the new keys. The success signal is a round trip that
  happens entirely after the rekey: the client sends "ping" (deferred through
  the rekey send-blackout), the server replies "pong", and only the "pong"
  completes the test. A broken rekey — wrong directional key switch, a dropped
  blackout flush, a mismatched exchange hash — prevents the round trip, so the
  long-test timeout fires instead of a false pass on a teardown.
  """
  fun name(): String => "integration/rekey"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)  // 10 second timeout

    let pem = _TestEd25519Pem()
    let server_config =
      try SshServerConfig(pem, "127.0.0.1", "19830")?
      else h.fail("invalid host key"); return
      end

    let server_notify = _RekeyServerNotify(h)
    let listen_auth = TCPListenAuth(h.env.root)
    let listener = SshListener(listen_auth, server_config, server_notify)
    server_notify.set_listener(listener)

    let client_config = SshClientConfig("127.0.0.1", "19830",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let connect_auth = TCPConnectAuth(h.env.root)
    SshConnector.connect(connect_auth, client_config, _RekeyClientNotify(h))


actor _RekeyClientNotify is SshClientNotify
  let _h: TestHelper
  var _done: Bool = false

  new create(h: TestHelper) =>
    _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    session.open_channel("session")

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("client auth failed: " + err.string())
    _h.complete(true)

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    // Re-exchange keys, then send data that must travel under the new keys.
    // channel_send is deferred through the rekey send-blackout and flushed
    // once our NEWKEYS is on the wire.
    session.rekey()
    session.channel_send(channel_id, "ping".array())

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    if String.from_array(data) == "pong" then
      // Round trip across the new keys succeeded.
      _done = true
      _h.complete(true)
      session.disconnect()
    end

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    if not _done then
      _h.fail("client error before rekey round trip: " + err.string())
      _h.complete(true)
    end

  be ssh_disconnected(session: SshSession tag) =>
    // Deliberately does not complete the test: a disconnect before the "pong"
    // round trip must surface as a timeout, not a pass.
    None


actor _RekeyServerNotify is SshServerNotify
  let _h: TestHelper
  var _listener: (SshListener tag | None) = None

  new create(h: TestHelper) =>
    _h = h

  be set_listener(listener: SshListener tag) =>
    _listener = listener

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_session_started(session: SshSession tag) =>
    match _listener
    | let l: SshListener tag =>
      l.dispose()
      _listener = None
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    // Reached only if the post-rekey "ping" decrypted correctly. Reply across
    // the new keys so the client can confirm the round trip.
    if String.from_array(data) == "ping" then
      session.channel_send(channel_id, "pong".array())
    end

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("server error: " + err.string())
    _h.complete(true)
