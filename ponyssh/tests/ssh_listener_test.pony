use "pony_test"
use "net"
use "../ssh_transport"
use "../ssh_auth"
use "../ssh_server"

class \nodoc\ iso _TestListenerBindFailure is UnitTest
  """
  Reports a successful bind and a failed bind with the corresponding listener.
  """
  fun name(): String => "ssh_server/listener/bind_failure"

  fun apply(h: TestHelper) =>
    h.long_test(10_000_000_000)

    let config =
      try SshServerConfig(_TestEd25519Pem(), "127.0.0.1", "19832")?
      else h.fail("invalid host key"); return
      end
    _BindFailureNotify(h, config, TCPListenAuth(h.env.root))


actor \nodoc\ _BindFailureNotify is SshServerNotify
  """
  Checks the bind outcome and identity of two listeners sharing one notify.
  """
  let _h: TestHelper
  let _config: SshServerConfig val
  let _auth: TCPListenAuth
  let _first: DisposableActor tag
  var _second: (DisposableActor tag | None) = None

  new create(h: TestHelper, config: SshServerConfig val, auth: TCPListenAuth) =>
    _h = h
    _config = config
    _auth = auth
    let first = SshListener(auth, config, this)
    _first = first
    h.dispose_when_done(first)

  fun validate_password(username: String val, password: String val): Bool =>
    false

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool => false

  be ssh_listener_started(listener: DisposableActor tag) =>
    match _second
    | None =>
      _h.assert_true(listener is _first,
        "the start was reported for a listener other than the first")
      let second = SshListener(_auth, _config, this)
      _second = second
      _h.dispose_when_done(second)
    else
      _h.fail("a second listener bound the address the first already holds")
      _h.complete(true)
    end

  be ssh_listener_failed(listener: DisposableActor tag) =>
    match _second
    | let second: DisposableActor tag =>
      _h.assert_true(listener is second,
        "the failure was reported for a listener other than the second")
    else
      _h.fail("a listener failed before the first had started")
    end
    _h.complete(true)
