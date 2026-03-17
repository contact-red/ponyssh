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

    let server_notify = _IntegrationServerNotify(h)
    let listen_auth = TCPListenAuth(h.env.root)
    let listener = SshListener(listen_auth, server_config, server_notify)
    server_notify.set_listener(listener)

    let client_config = SshClientConfig("127.0.0.1", "19827",
      "testuser",
      recover val [as SshAuthMethod val: SshNoneAuth] end)
    let connect_auth = TCPConnectAuth(h.env.root)
    SshConnector.connect(connect_auth, client_config,
      _IntegrationClientNotify(h))


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
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) => None

  be ssh_disconnected(session: SshSession tag) =>
    _h.complete(true)


actor _IntegrationServerNotify is SshServerNotify
  let _h: TestHelper
  var _listener: (SshListener tag | None) = None

  new create(h: TestHelper) =>
    _h = h

  be set_listener(listener: SshListener tag) =>
    _listener = listener

  be ssh_session_started(session: SshSession tag) => None

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    session.auth_accept()

  be ssh_session_ready(session: SshSession tag) => None

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

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
