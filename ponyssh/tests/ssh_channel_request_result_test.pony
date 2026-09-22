use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"
use "../ssh_server"

class \nodoc\ iso _TestChannelRequestResults is UnitTest
  var _client: (_RequestResultClient tag | None) = None

  fun name(): String => "integration/channel_request_results"

  fun ref apply(h: TestHelper) =>
    h.long_test(10_000_000_000)
    let config =
      match MakeSshServerConfig(_TestEd25519Pem(), "127.0.0.1", "19833")
      | let ready: SshServerConfig val => ready
      | let err: SshServerConfigError => h.fail(err.string()); return
      end
    let client_config = SshClientConfig("127.0.0.1", "19833",
      "testuser",
      recover val [as SshAuthMethod val: SshPasswordAuth("testpw")] end)
    let client = _RequestResultClient(h)
    _client = client
    let server = _RequestResultServer(TCPConnectAuth(h.env.root),
      client_config, client)
    h.dispose_when_done(SshListener(TCPListenAuth(h.env.root), config,
      server))

  fun ref timed_out(h: TestHelper) =>
    match _client
    | let client: _RequestResultClient tag => client.stop()
    end

actor \nodoc\ _RequestResultClient is SshClientNotify
  let _h: TestHelper
  var _session: (SshSession tag | None) = None
  var _channel_id: U32 = 0
  var _second_channel_id: (U32 | None) = None
  var _opened: USize = 0
  var _results: USize = 0
  var _markers: USize = 0

  new create(h: TestHelper) => _h = h

  be set_session(session: SshSession tag) => _session = session

  be stop() =>
    match _session
    | let session: SshSession tag => session.disconnect()
    end

  be ssh_verify_host_key(session: SshSession tag, host: String val,
    key: SshHostKey val)
  =>
    session.accept_host_key()

  be ssh_ready(session: SshSession tag) =>
    session.open_channel("session")
    session.channel_request_shell(0)
    session.channel_request_exec(0, "early")

  be ssh_channel_opened(session: SshSession tag, channel_id: U32) =>
    _opened = _opened + 1
    if _opened == 1 then
      _channel_id = channel_id
      session.channel_request_shell(channel_id)
    elseif _opened == 2 then
      _h.assert_false(_channel_id == channel_id)
      _second_channel_id = channel_id
      session.channel_request_shell(channel_id)
      session.channel_request_shell(channel_id)
    else
      _h.fail("unexpected channel open")
      session.disconnect()
    end

  be ssh_channel_request_result(session: SshSession tag, channel_id: U32,
    accepted: Bool)
  =>
    _results = _results + 1
    if _results == 1 then
      _h.assert_eq[U32](_channel_id, channel_id)
      _h.assert_eq[USize](0, _markers)
      _h.assert_true(accepted)
      session.channel_request_exec(channel_id, "false")
    elseif _results == 2 then
      _h.assert_eq[U32](_channel_id, channel_id)
      _h.assert_eq[USize](0, _markers)
      _h.assert_false(accepted)
      session.channel_request_shell(channel_id, false)
    elseif _results == 3 then
      match _second_channel_id
      | let second: U32 => _h.assert_eq[U32](second, channel_id)
      | None => _h.fail("second channel was not opened")
      end
      _h.assert_eq[USize](2, _markers)
      _h.assert_true(accepted)
    elseif _results == 4 then
      match _second_channel_id
      | let second: U32 => _h.assert_eq[U32](second, channel_id)
      | None => _h.fail("second channel was not opened")
      end
      _h.assert_false(accepted)
      session.disconnect()
    else
      _h.fail("unexpected channel request reply")
      session.disconnect()
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    _h.assert_eq[U32](_channel_id, channel_id)
    _h.assert_eq[USize](2, _results)
    _markers = _markers + 1
    if _markers == 1 then
      _h.assert_eq[String]("no-reply-processed", String.from_array(data))
      session.channel_request_shell(channel_id, false)
    elseif _markers == 2 then
      _h.assert_eq[String]("unsolicited-reply-ignored",
        String.from_array(data))
      session.open_channel("session")
    else
      _h.fail("unexpected channel data")
      session.disconnect()
    end

  be ssh_disconnected(session: SshSession tag) =>
    _h.assert_eq[USize](2, _markers)
    _h.assert_eq[USize](4, _results)
    _h.complete(true)

  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val) =>
    _h.fail("authentication failed: " + err.string())
    session.disconnect()
    _h.complete(true)

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val)
  =>
    _h.fail("channel failed: " + err.string())
    session.disconnect()
    _h.complete(true)

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None
  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _h.fail("client error: " + err.string())
    session.disconnect()
    _h.complete(true)

actor \nodoc\ _RequestResultServer is SshServerNotify
  let _connect_auth: TCPConnectAuth
  let _client_config: SshClientConfig val
  let _client: _RequestResultClient tag
  var _first_channel_id: (U32 | None) = None
  var _requests: USize = 0

  new create(connect_auth: TCPConnectAuth, config: SshClientConfig val,
    client: _RequestResultClient tag)
  =>
    _connect_auth = connect_auth
    _client_config = config
    _client = client

  be ssh_listener_started(listener: DisposableActor tag) =>
    let session = SshConnector.connect(_connect_auth, _client_config, _client)
    _client.set_session(session)

  fun validate_password(username: String val, password: String val): Bool =>
    password == "testpw"

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    if _first_channel_id is None then _first_channel_id = channel_id end
    session.accept_channel(channel_id)

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    _requests = _requests + 1
    if _requests == 1 then
      if want_reply then session.accept_request(channel_id) end
    elseif _requests == 3 then
      if not want_reply then
        session.channel_send(channel_id, "no-reply-processed".array())
      end
    elseif _requests == 4 then
      if not want_reply then
        session.accept_request(channel_id)
        session.channel_send(channel_id,
          "unsolicited-reply-ignored".array())
      end
    elseif _requests == 5 then
      match _first_channel_id
      | let first: U32 => session.accept_request(first)
      end
      if want_reply then session.accept_request(channel_id) end
    elseif _requests == 6 then
      if want_reply then session.reject_request(channel_id) end
    end

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  =>
    _requests = _requests + 1
    if (request_type == "exec") and want_reply then
      session.reject_request(channel_id)
    end

  be ssh_channel_send_result(session: SshSession tag, channel_id: U32,
    data: Array[U8] val, accepted: USize, outcome: SshSendOutcome) => None

  be ssh_channel_window_available(session: SshSession tag,
    channel_id: U32) => None
