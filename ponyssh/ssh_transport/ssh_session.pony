use "lori"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_auth"
use "../ssh_connection"

type _SshBridge is (_SshClientTcpBridge tag | _SshServerTcpBridge tag)

class val SshClientConfig
  let host: String val
  let port: String val
  let username: String val
  let auth_methods: Array[SshAuthMethod val] val
  let algorithms: (SshAlgorithmPreferences val | None)

  new val create(host': String val, port': String val,
    username': String val = "",
    auth_methods': Array[SshAuthMethod val] val =
      recover val Array[SshAuthMethod val] end,
    algorithms': (SshAlgorithmPreferences val | None) = None)
  =>
    host = host'
    port = port'
    username = username'
    auth_methods = auth_methods'
    algorithms = algorithms'

class val SshServerConfig
  let host_key_pem: Array[U8] val
  let algorithms: (SshAlgorithmPreferences val | None)

  new val create(host_key_pem': Array[U8] val,
    algorithms': (SshAlgorithmPreferences val | None) = None)
  =>
    host_key_pem = host_key_pem'
    algorithms = algorithms'

actor SshSession
  let _role: SshRole
  let _client_notify: (SshClientNotify tag | None)
  let _server_notify: (SshServerNotify tag | None)
  var _bridge: (_SshBridge | None) = None
  var _state: SshSessionState = SshStateHandshake
  let _context: SshSessionContext = SshSessionContext
  let _reader: SshPacketReader = SshPacketReader
  let _writer: SshPacketWriter = SshPacketWriter
  let _channel_manager: SshChannelManager = SshChannelManager
  var _prefs: SshAlgorithmPreferences val = SshDefaultAlgorithms.preferences()
  var _kex: (SshKexStateMachine | None) = None
  var _auth: (SshAuthStateMachine | None) = None

  let _version_string: String val = "SSH-2.0-ponyssh_0.1"

  // --- Factory constructors ---

  new create_client(auth: TCPConnectAuth, config: SshClientConfig val,
    notify: SshClientNotify tag)
  =>
    _role = SshRoleClient
    _client_notify = notify
    _server_notify = None
    match config.algorithms
    | let p: SshAlgorithmPreferences val => _prefs = p
    end
    _kex = SshKexStateMachine(SshRoleClient)
    _auth = SshAuthStateMachine(config.username, config.auth_methods)
    _bridge = _SshClientTcpBridge(auth, config.host, config.port, this)

  new create_server(config: SshServerConfig val, notify: SshServerNotify tag) =>
    _role = SshRoleServer
    _client_notify = None
    _server_notify = notify
    match config.algorithms
    | let p: SshAlgorithmPreferences val => _prefs = p
    end
    _kex = SshKexStateMachine(SshRoleServer)
    _auth = None
    // Bridge set separately via _set_bridge

  be _set_bridge(bridge: _SshServerTcpBridge tag) =>
    _bridge = bridge

  // --- Public behaviors (called by consumers) ---

  be open_channel(channel_type: String val = "session") =>
    match _state
    | let _: SshStateConnected =>
      let local_id = _channel_manager.open_channel(channel_type)
      _send_packet(SshChannelMessages.channel_open(channel_type, local_id,
        0x200000, 0x8000))
    end

  be channel_send(channel_id: U32, data: Array[U8] val) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.channel_data_send(channel_id, data.size())
      | let remote_id: U32 =>
        _send_packet(SshChannelMessages.channel_data(remote_id, data))
      | let err: SshChannelError =>
        _notify_channel_error(channel_id, err)
      end
    end

  be channel_close(channel_id: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.channel_data_send(channel_id, 0)
      | let remote_id: U32 =>
        _send_packet(SshChannelMessages.channel_eof(remote_id))
        _send_packet(SshChannelMessages.channel_close(remote_id))
        _channel_manager.close_channel(channel_id)
        _notify_channel_closed(channel_id)
      | let _: SshChannelError => None  // Already closed
      end
    end

  be accept_host_key() =>
    match _state
    | let s: SshStateKeyExchange =>
      s.awaiting_host_key_verification = false
      // TODO: implement continuation after host key verification
    end

  be reject_host_key() =>
    _disconnect_with_error(SshProtocolVersionMismatch)

  be auth_accept() =>
    match _state
    | let _: SshStateAuth =>
      _send_packet(SshAuthMessages.userauth_success())
      let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else
        recover val Array[U8] end
      end
      _state = SshStateConnected(session_id)
      match _server_notify
      | let n: SshServerNotify tag => n.ssh_session_ready(this)
      end
    end

  be auth_reject(remaining: Array[String val] val) =>
    match _state
    | let _: SshStateAuth =>
      _send_packet(SshAuthMessages.userauth_failure(remaining, false))
    end

  be accept_channel(channel_id: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        _send_packet(SshChannelMessages.channel_open_confirmation(
          ch.remote_id, ch.local_id, 0x200000, 0x8000))
      end
    end

  be reject_channel(channel_id: U32, reason: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        _send_packet(SshChannelMessages.channel_open_failure(
          ch.remote_id, reason, "rejected"))
        _channel_manager.close_channel(channel_id)
      end
    end

  // --- Internal behaviors (called by TCP bridge) ---

  be _tcp_connected() =>
    _send_version()

  be _tcp_received(data: Array[U8] iso) =>
    _reader.append(consume data)
    _process_packets()

  be _tcp_closed() =>
    _state = SshStateDisconnected(SshConnectionLost)
    _notify_disconnected()

  be _tcp_connection_failed() =>
    _state = SshStateDisconnected(SshConnectionLost)
    _notify_error(SshConnectionLost)
    _notify_disconnected()

  // --- Private methods ---

  fun ref _send_version() =>
    """Send SSH version string."""
    match _bridge
    | let b: _SshClientTcpBridge tag =>
      b.write(_version_string + "\r\n")
    | let b: _SshServerTcpBridge tag =>
      b.write(_version_string + "\r\n")
    end

  fun ref _process_packets() =>
    """Read and dispatch packets from the reader."""
    match _state
    | let s: SshStateHandshake =>
      _handle_version_exchange(s)
      return
    end

    while true do
      match _reader.read()
      | let payload: Array[U8] val => _dispatch_packet(payload)
      | let err: SshTransportError =>
        _disconnect_with_error(err)
        return
      | None => return
      end
    end

  fun ref _handle_version_exchange(state: SshStateHandshake) =>
    """
    Parse the remote version string from the buffered data.
    Stub -- will be completed with integration tests.
    """
    None

  fun ref _dispatch_packet(payload: Array[U8] val) =>
    """Route a decrypted payload to the appropriate handler based on state."""
    try
      let msg_type = payload(0)?
      match _state
      | let _: SshStateHandshake => None
      | let _: SshStateKeyExchange => _handle_kex(msg_type, payload)
      | let _: SshStateAuth => _handle_auth(msg_type, payload)
      | let s: SshStateConnected => _handle_connected(msg_type, payload, s)
      | let _: SshStateDisconnected => None
      end
    end

  fun ref _handle_kex(msg_type: U8, payload: Array[U8] val) =>
    """Handle messages during key exchange."""
    match msg_type
    | SshMsgTypes.kexinit() =>
      match _kex
      | let kex: SshKexStateMachine =>
        match kex.receive_kexinit(payload, _prefs)
        | let neg: SshNegotiatedAlgorithms val =>
          _context.negotiated_algorithms = neg
          // TODO: Start DH/ECDH exchange
        | let err: SshTransportError =>
          _disconnect_with_error(err)
        end
      end
    | SshMsgTypes.newkeys() =>
      let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else
        recover val Array[U8] end
      end
      _state = SshStateAuth(session_id)
      match _role
      | SshRoleClient =>
        _send_packet(SshAuthMessages.service_request("ssh-userauth"))
      end
    end

  fun ref _handle_auth(msg_type: U8, payload: Array[U8] val) =>
    """Handle messages during authentication."""
    match msg_type
    | SshAuthMsgTypes.userauth_success() =>
      let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else
        recover val Array[U8] end
      end
      _state = SshStateConnected(session_id)
      match _client_notify
      | let n: SshClientNotify tag => n.ssh_ready(this)
      end
    | SshAuthMsgTypes.userauth_failure() =>
      match _auth
      | let auth_sm: SshAuthStateMachine =>
        match auth_sm.handle_failure()
        | let req: Array[U8] val =>
          _send_packet(req)
        | SshAuthRejected =>
          match _client_notify
          | let n: SshClientNotify tag =>
            n.ssh_auth_failed(this, SshAuthRejected)
          end
          _disconnect_with_error(SshConnectionLost)
        end
      end
    | SshAuthMsgTypes.userauth_request() =>
      // Server side: decode and forward to consumer
      // TODO: decode auth request and forward
      None
    | SshAuthMsgTypes.service_request() =>
      match _role
      | SshRoleServer =>
        try
          let r = SshWireReader(payload)
          r.read_byte()?  // msg type
          let service = r.read_string_as_str()?
          let w = SshWireWriter
          w.write_byte(SshAuthMsgTypes.service_accept())
          w.write_string_from_str(service)
          _send_packet(w.val_bytes())
        end
      end
    end

  fun ref _handle_connected(msg_type: U8, payload: Array[U8] val,
    state: SshStateConnected)
  =>
    """Handle messages when connected (channel operations + rekey)."""
    match msg_type
    | SshChannelMsgTypes.channel_open() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let ch_type = r.read_string_as_str()?
        let sender_channel = r.read_u32()?
        let initial_window = r.read_u32()?
        let max_packet = r.read_u32()?
        let local_id = _channel_manager.accept_channel(
          0, sender_channel, initial_window, max_packet, ch_type)
        match _server_notify
        | let n: SshServerNotify tag =>
          n.ssh_channel_open_request(this, local_id, ch_type)
        end
      end
    | SshChannelMsgTypes.channel_open_confirmation() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let sender_channel = r.read_u32()?
        let initial_window = r.read_u32()?
        let max_packet = r.read_u32()?
        _channel_manager.confirm_channel(recipient_channel, sender_channel,
          initial_window, max_packet)
        _notify_channel_opened(recipient_channel)
      end
    | SshChannelMsgTypes.channel_open_failure() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let reason_code = r.read_u32()?
        let description = r.read_string_as_str()?
        _channel_manager.close_channel(recipient_channel)
        _notify_channel_error(recipient_channel,
          SshChannelOpenFailed(reason_code, description))
      end
    | SshChannelMsgTypes.channel_data() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let data = r.read_string()?
        _channel_manager.channel_data_received(recipient_channel, data.size())
        _notify_channel_data(recipient_channel, data)
      end
    | SshChannelMsgTypes.channel_window_adjust() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let bytes_to_add = r.read_u32()?
        _channel_manager.window_adjust(recipient_channel, bytes_to_add)
      end
    | SshChannelMsgTypes.channel_eof() =>
      None
    | SshChannelMsgTypes.channel_close() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        _channel_manager.close_channel(recipient_channel)
        _notify_channel_closed(recipient_channel)
      end
    | SshMsgTypes.kexinit() =>
      // Rekeying
      state.rekeying = true
      _handle_kex(msg_type, payload)
    | SshMsgTypes.disconnect() =>
      _state = SshStateDisconnected(SshConnectionLost)
      _notify_disconnected()
    end

  fun ref _send_packet(payload: Array[U8] val) =>
    """Frame and send a packet."""
    let block_size: USize = _current_block_size()
    let packet = _writer.write(payload, block_size)
    match _bridge
    | let b: _SshClientTcpBridge tag => b.write(consume packet)
    | let b: _SshServerTcpBridge tag => b.write(consume packet)
    end

  fun _current_block_size(): USize =>
    """Return cipher block size, or 8 for plaintext."""
    8  // TODO: return actual cipher block size when encrypted

  fun ref _disconnect_with_error(err: SshTransportError) =>
    """Send SSH_MSG_DISCONNECT and transition to Disconnected."""
    _send_packet(SshMessages.disconnect(
      SshDisconnectCodes.protocol_error(), err.string()))
    match _bridge
    | let b: _SshClientTcpBridge tag => b.close()
    | let b: _SshServerTcpBridge tag => b.close()
    end
    _state = SshStateDisconnected(err)
    _notify_error(err)
    _notify_disconnected()

  // --- Notification helpers ---

  fun ref _notify_error(err: SshTransportError) =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_error(this, err)
    end
    match _server_notify
    | let n: SshServerNotify tag => n.ssh_error(this, err)
    end

  fun ref _notify_disconnected() =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_disconnected(this)
    end
    match _server_notify
    | let n: SshServerNotify tag => n.ssh_disconnected(this)
    end

  fun ref _notify_channel_opened(channel_id: U32) =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_channel_opened(this, channel_id)
    end

  fun ref _notify_channel_data(channel_id: U32, data: Array[U8] val) =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_channel_data(this, channel_id, data)
    end
    match _server_notify
    | let n: SshServerNotify tag => n.ssh_channel_data(this, channel_id, data)
    end

  fun ref _notify_channel_error(channel_id: U32, err: SshChannelError) =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_channel_error(this, channel_id, err)
    end
    match _server_notify
    | let n: SshServerNotify tag => n.ssh_channel_error(this, channel_id, err)
    end

  fun ref _notify_channel_closed(channel_id: U32) =>
    match _client_notify
    | let n: SshClientNotify tag => n.ssh_channel_closed(this, channel_id)
    end
    match _server_notify
    | let n: SshServerNotify tag => n.ssh_channel_closed(this, channel_id)
    end
