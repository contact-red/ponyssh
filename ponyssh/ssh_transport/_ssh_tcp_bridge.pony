use "lori"

actor SshClientTcpBridge is (TCPConnectionActor & ClientLifecycleEventReceiver)
  var _tcp_connection: TCPConnection = TCPConnection.none()
  let _session: SshSession tag

  new create(auth: TCPConnectAuth, host: String, port: String,
    session: SshSession tag)
  =>
    _session = session
    _tcp_connection = TCPConnection.client(auth, host, port, "", this, this)

  fun ref _connection(): TCPConnection => _tcp_connection

  fun ref _on_connected() =>
    _session._tcp_connected()

  fun ref _on_connection_failure(reason: ConnectionFailureReason) =>
    _session._tcp_connection_failed()

  fun ref _on_received(data: Array[U8] iso) =>
    _session._tcp_received(consume data)

  fun ref _on_closed() =>
    _session._tcp_closed()

  be write(data: ByteSeq) =>
    _connection().send(data)

  be close() =>
    _connection().close()

actor SshServerTcpBridge is (TCPConnectionActor & ServerLifecycleEventReceiver)
  var _tcp_connection: TCPConnection = TCPConnection.none()
  let _session: SshSession tag

  new create(auth: TCPServerAuth, fd: U32, session: SshSession tag) =>
    _session = session
    _tcp_connection = TCPConnection.server(auth, fd, this, this)

  fun ref _connection(): TCPConnection => _tcp_connection

  fun ref _on_started() =>
    _session._tcp_connected()

  fun ref _on_received(data: Array[U8] iso) =>
    _session._tcp_received(consume data)

  fun ref _on_closed() =>
    _session._tcp_closed()

  be write(data: ByteSeq) =>
    _connection().send(data)

  be close() =>
    _connection().close()
