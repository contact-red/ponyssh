use "pony_test"
use "lori"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class iso _TestIntegrationChannelFlowControl is UnitTest
  fun name(): String => "integration/channel_flow_control"

  fun apply(h: TestHelper) =>
    h.long_test(15_000_000_000)

    let server_config = try
      SshServerConfig(_TestEd25519Pem(), "127.0.0.1", "19831")?
    else
      h.fail("invalid host key")
      return
    end
    let server_notify = _FlowControlServerNotify(h)
    let listener = SshListener(
      TCPListenAuth(h.env.root), server_config, server_notify)
    server_notify.set_listener(listener)

    let client_config = SshClientConfig("127.0.0.1", "19831", "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    SshConnector.connect(TCPConnectAuth(h.env.root), client_config,
      _FlowControlClientNotify(h))

actor _FlowControlClientNotify is SshClientNotify
  let _h: TestHelper

  new create(h: TestHelper) => _h = h

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) => session.open_channel()

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    let size = SshChannelWindow.initial().usize() + 65536
    let payload = recover val
      let data = Array[U8].init(0x5a, size)
      data
    end
    session.channel_send(channel_id, payload)

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("client auth failed: " + err.string())
    _h.complete(true)

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val)
  =>
    _h.fail("client channel error: " + err.string())
    _h.complete(true)

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_disconnected(session: SshSession tag) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("client transport error: " + err.string())
    _h.complete(true)

actor _FlowControlServerNotify is SshServerNotify
  let _h: TestHelper
  let _expected: USize = SshChannelWindow.initial().usize() + 65536
  var _received: USize = 0
  var _listener: (SshListener tag | None) = None

  new create(h: TestHelper) => _h = h

  be set_listener(listener: SshListener tag) => _listener = listener

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool
  =>
    false

  be ssh_session_started(session: SshSession tag) =>
    match _listener
    | let listener: SshListener tag =>
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
    for byte in data.values() do
      if byte != 0x5a then
        _h.fail("received corrupt channel data")
        _h.complete(true)
        session.disconnect()
        return
      end
    end
    _received = _received + data.size()
    if _received > _expected then
      _h.fail("received duplicate channel data")
      _h.complete(true)
      session.disconnect()
    elseif _received == _expected then
      _h.complete(true)
      session.disconnect()
    end

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("server transport error: " + err.string())
    _h.complete(true)
