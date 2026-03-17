use "lori"
use "../ssh_transport"

actor SshListener is TCPListenerActor
  var _tcp_listener: TCPListener = TCPListener.none()
  let _config: SshServerConfig val
  let _notify: SshServerNotify tag
  let _auth: TCPListenAuth

  new create(auth: TCPListenAuth, config: SshServerConfig val,
    notify: SshServerNotify tag)
  =>
    _config = config
    _notify = notify
    _auth = auth
    _tcp_listener = TCPListener(auth, config.listen_host, config.listen_port, this)

  fun ref _listener(): TCPListener => _tcp_listener

  fun ref _on_accept(fd: U32): SshServerTcpBridge =>
    let server_auth = TCPServerAuth(_auth)
    let session = SshSession.create_server(_config, _notify)
    let bridge = SshServerTcpBridge(server_auth, fd, session)
    session.set_server_bridge(bridge)
    _notify.ssh_session_started(session)
    bridge

  fun ref _on_listening() => None
  fun ref _on_listen_failure() => None
  fun ref _on_closed() => None
