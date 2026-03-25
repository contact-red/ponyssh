use "lori"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_auth"
use "../ssh_connection"

type _SshBridge is (SshClientTcpBridge tag | SshServerTcpBridge tag)

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
  let listen_host: String val
  let listen_port: String val
  let algorithms: (SshAlgorithmPreferences val | None)

  new val create(host_key_pem': Array[U8] val,
    listen_host': String val = "127.0.0.1",
    listen_port': String val = "22",
    algorithms': (SshAlgorithmPreferences val | None) = None)
  =>
    host_key_pem = host_key_pem'
    listen_host = listen_host'
    listen_port = listen_port'
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
  var _host_key: (SshHostKeyPair | None) = None
  var _our_kexinit: (Array[U8] val | None) = None
  var _encrypted: Bool = false

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
    _bridge = SshClientTcpBridge(auth, config.host, config.port, this)

  new create_server(config: SshServerConfig val, notify: SshServerNotify tag) =>
    _role = SshRoleServer
    _client_notify = None
    _server_notify = notify
    match config.algorithms
    | let p: SshAlgorithmPreferences val => _prefs = p
    end
    _kex = SshKexStateMachine(SshRoleServer)
    _auth = None
    try _host_key = SshHostKeyPair.create(config.host_key_pem)? end
    // Bridge set separately via _set_bridge

  be _set_bridge(bridge: SshServerTcpBridge tag) =>
    _bridge = bridge

  be set_server_bridge(bridge: SshServerTcpBridge tag) =>
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
    // NEWKEYS was already sent when the signature was verified.
    // This just clears the awaiting flag. If we've already transitioned
    // to Auth (received server's NEWKEYS), this is a no-op.
    match _state
    | let s: SshStateKeyExchange =>
      s.awaiting_host_key_verification = false
    end

  be reject_host_key() =>
    _disconnect_with_error(SshProtocolVersionMismatch)

  be disconnect(msg: String val = "") =>
    """Clean disconnect initiated by consumer."""
    _send_packet(SshMessages.disconnect(
      SshDisconnectCodes.by_application(), msg))
    _close_bridge()
    _state = SshStateDisconnected(None)
    _notify_disconnected()

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

  be auth_pk_ok(algorithm: String val, public_key: Array[U8] val) =>
    match _state
    | let _: SshStateAuth =>
      _send_packet(SshAuthMessages.userauth_pk_ok(algorithm, public_key))
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

  be accept_request(channel_id: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        ch.pty_pending = false
        _send_packet(SshChannelMessages.channel_success(ch.remote_id))
      end
    end

  be reject_request(channel_id: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        if ch.pty_pending then
          ch.pty = None
          ch.pty_pending = false
        end
        _send_packet(SshChannelMessages.channel_failure(ch.remote_id))
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

  // --- Crypto worker result behaviors ---

  be _kex_computed(our_public: Array[U8] val, shared_secret: Array[U8] val) =>
    """Crypto worker completed key exchange computation."""
    match _state
    | let s: SshStateKeyExchange =>
      s.shared_secret = shared_secret
      // TODO: compute exchange hash, verify host key, send NEWKEYS
      // For now, just store the result
    end

  be _kex_failed(err: SshKexFailed) =>
    """Crypto worker failed key exchange."""
    _disconnect_with_error(err)

  // --- Private methods ---

  fun ref _send_version() =>
    """Send SSH version string."""
    match _bridge
    | let b: SshClientTcpBridge tag =>
      b.write(_version_string + "\r\n")
    | let b: SshServerTcpBridge tag =>
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
    Version exchange is raw line-based text before packet framing begins.
    Lines not starting with "SSH-" are pre-auth banners (ignored per RFC 4253).
    The version line must start with "SSH-2.0-".
    """
    while true do
      match _reader.read_line()
      | let line: String val =>
        if line.substring(0, 4) == "SSH-" then
          // This is the version string
          if line.substring(0, 8) != "SSH-2.0-" then
            _disconnect_with_error(SshProtocolVersionMismatch)
            return
          end
          _context.remote_version = line
          // Send our KEXINIT and transition to key exchange
          match _kex
          | let kex: SshKexStateMachine =>
            let our_kexinit = kex.generate_kexinit(_prefs)
            _our_kexinit = our_kexinit
            _send_packet(our_kexinit)
            // Transition to KeyExchange state. We don't yet have their KEXINIT,
            // so create the state with placeholder empty arrays and negotiated.
            // The real negotiation happens when we receive their KEXINIT.
            let empty: Array[U8] val = recover val Array[U8] end
            let placeholder_neg = SshNegotiatedAlgorithms("", "", "", "", "", "")
            _state = SshStateKeyExchange(our_kexinit, empty, placeholder_neg)
          end
          // Try processing any remaining buffered data as packets
          _process_packets()
          return
        end
        // Non-SSH lines are pre-auth banners, skip them
      | None =>
        return  // Not enough data yet
      end
    end

  fun ref _dispatch_packet(payload: Array[U8] val) =>
    """Route a decrypted payload to the appropriate handler based on state."""
    try
      let msg_type = payload(0)?

      // Global messages handled in any state (RFC 4253 §11)
      match msg_type
      | SshMsgTypes.disconnect() =>
        _state = SshStateDisconnected(SshConnectionLost)
        _notify_disconnected()
        return
      | SshMsgTypes.ignore() => return    // silently discard
      | SshMsgTypes.debug() => return     // silently discard
      | SshMsgTypes.unimplemented() => return  // peer couldn't handle something
      | SshMsgTypes.ext_info() => return  // extensions info, safe to ignore
      end

      // State-specific routing
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
          // Update state with their KEXINIT and negotiated algorithms
          let our_ki = match _our_kexinit
          | let ki: Array[U8] val => ki
          else
            recover val Array[U8] end
          end
          _state = SshStateKeyExchange(our_ki, payload, neg)
          // Client initiates ECDH after receiving server's KEXINIT
          match _role
          | SshRoleClient =>
            try
              let client_kex = SshKexCurve25519.create()?
              let client_pub = client_kex.public_key()
              // Store kex object in state for later use
              match _state
              | let s: SshStateKeyExchange =>
                s.our_kex = client_kex
              end
              _send_packet(SshMessages.kex_ecdh_init(client_pub))
            else
              _disconnect_with_error(SshKexFailed(SshKeyInvalid))
            end
          end
        | let err: SshTransportError =>
          _disconnect_with_error(err)
        end
      end
    | SshMsgTypes.kex_ecdh_init() =>
      // Server receives client's public key
      match _role
      | SshRoleServer =>
        match _state
        | let s: SshStateKeyExchange =>
          try
            let r = SshWireReader(payload)
            r.read_byte()?  // msg type
            let client_pub = r.read_string()?
            _server_handle_ecdh_init(s, client_pub)
          else
            _disconnect_with_error(SshKexFailed(SshKeyInvalid))
          end
        end
      end
    | SshMsgTypes.kex_ecdh_reply() =>
      // Client receives server's reply
      match _role
      | SshRoleClient =>
        match _state
        | let s: SshStateKeyExchange =>
          try
            let r = SshWireReader(payload)
            r.read_byte()?  // msg type
            let host_key_blob = r.read_string()?
            let server_pub = r.read_string()?
            let signature = r.read_string()?
            _client_handle_ecdh_reply(s, host_key_blob, server_pub, signature)
          else
            _disconnect_with_error(SshKexFailed(SshKeyInvalid))
          end
        end
      end
    | SshMsgTypes.newkeys() =>
      let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else
        recover val Array[U8] end
      end
      // Activate encryption using stored key exchange results
      match _state
      | let kex_s: SshStateKeyExchange =>
        _activate_encryption(kex_s, session_id)
      end
      _state = SshStateAuth(session_id)
      match _role
      | SshRoleClient =>
        _send_packet(SshAuthMessages.service_request("ssh-userauth"))
      end
    end

  fun ref _server_handle_ecdh_init(s: SshStateKeyExchange,
    client_pub: Array[U8] val)
  =>
    """
    Server handles SSH_MSG_KEX_ECDH_INIT: generate keypair, compute shared
    secret, compute exchange hash per RFC 4253 section 8, sign it,
    send reply + NEWKEYS.
    """
    try
      let server_kex = SshKexCurve25519.create()?
      let server_pub = server_kex.public_key()

      match server_kex.derive_shared_secret(client_pub)
      | let shared_secret: Array[U8] val =>
        // Build host key blob first (needed for exchange hash)
        match _host_key
        | let hk: SshHostKeyPair =>
          let pub_key = hk.public_key()
          let host_key_blob = recover val
            let w = SshWireWriter
            w.write_string_from_str(pub_key.algorithm)
            w.write_string(pub_key.public_key_data)
            w.val_bytes()
          end

          // Compute full exchange hash per RFC 4253 section 8 / RFC 8731:
          // H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
          //           || string(K_S) || string(Q_C) || string(Q_S) || mpint(K))
          let client_version = match _context.remote_version
          | let v: String val => v
          else ""
          end
          let server_version: String val = _version_string
          let exchange_hash = _compute_exchange_hash(
            client_version, server_version,
            s.their_kexinit, s.our_kexinit,
            host_key_blob, client_pub, server_pub, shared_secret)

          // Set session_id (first exchange hash per RFC 4253)
          if _context.session_id is None then
            _context.session_id = exchange_hash
          end

          // Store shared secret and exchange hash for key derivation after NEWKEYS
          s.shared_secret = shared_secret
          s.exchange_hash = exchange_hash

          match hk.sign(exchange_hash)
          | let raw_sig: Array[U8] val =>
            let sig_blob = recover val
              let w = SshWireWriter
              w.write_string_from_str(pub_key.algorithm)
              w.write_string(raw_sig)
              w.val_bytes()
            end

            _send_packet(SshMessages.kex_ecdh_reply(host_key_blob, server_pub,
              sig_blob))
            _send_packet(SshMessages.newkeys())
          | let err: SshCryptoError =>
            _disconnect_with_error(SshKexFailed(err))
          end
        else
          _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        end
      | let err: SshCryptoError =>
        _disconnect_with_error(SshKexFailed(err))
      end
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
    end

  fun ref _client_handle_ecdh_reply(s: SshStateKeyExchange,
    host_key_blob: Array[U8] val, server_pub: Array[U8] val,
    signature: Array[U8] val)
  =>
    """
    Client handles SSH_MSG_KEX_ECDH_REPLY: compute shared secret,
    compute exchange hash per RFC 4253 section 8, verify signature,
    request host key verification.
    """
    match s.our_kex
    | let client_kex: SshKexCurve25519 =>
      let client_pub = client_kex.public_key()
      match client_kex.derive_shared_secret(server_pub)
      | let shared_secret: Array[U8] val =>
        // Compute full exchange hash per RFC 4253 section 8 / RFC 8731
        let client_version: String val = _version_string
        let server_version = match _context.remote_version
        | let v: String val => v
        else ""
        end
        let exchange_hash = _compute_exchange_hash(
          client_version, server_version,
          s.our_kexinit, s.their_kexinit,
          host_key_blob, client_pub, server_pub, shared_secret)

        // Set session_id
        if _context.session_id is None then
          _context.session_id = exchange_hash
        end

        // Store shared secret and exchange hash for key derivation after NEWKEYS
        s.shared_secret = shared_secret
        s.exchange_hash = exchange_hash

        // Parse host key blob to get SshHostKey
        try
          let kr = SshWireReader(host_key_blob)
          let algo = kr.read_string_as_str()?
          let pk_data = kr.read_string()?
          let host_key = SshHostKey(algo, pk_data)
          _context.server_host_key = host_key

          // Verify the signature on the exchange hash
          let sr = SshWireReader(signature)
          let sig_algo = sr.read_string_as_str()?
          let raw_sig = sr.read_string()?

          match SshHostKeyVerify.verify(host_key, raw_sig, exchange_hash)
          | true =>
            // Signature valid, send NEWKEYS immediately
            _send_packet(SshMessages.newkeys())
            // Notify consumer for host key verification (accept/reject
            // controls whether auth proceeds after we receive server NEWKEYS)
            s.awaiting_host_key_verification = true
            match _client_notify
            | let n: SshClientNotify tag =>
              n.ssh_verify_host_key(this, "", host_key)
            end
          | let err: SshCryptoError =>
            _disconnect_with_error(SshKexFailed(err))
          end
        else
          _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        end
      | let err: SshCryptoError =>
        _disconnect_with_error(SshKexFailed(err))
      end
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
    end

  fun _compute_exchange_hash(
    client_version: String val, server_version: String val,
    client_kexinit: Array[U8] val, server_kexinit: Array[U8] val,
    host_key_blob: Array[U8] val,
    client_pub: Array[U8] val, server_pub: Array[U8] val,
    shared_secret: Array[U8] val): Array[U8] val
  =>
    """
    Compute the full exchange hash per RFC 4253 section 8 / RFC 8731:
    H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
              || string(K_S) || string(Q_C) || string(Q_S) || mpint(K))
    """
    let hash_input = recover val
      let w = SshWireWriter
      w.write_string_from_str(client_version)
      w.write_string_from_str(server_version)
      w.write_string(client_kexinit)
      w.write_string(server_kexinit)
      w.write_string(host_key_blob)
      w.write_string(client_pub)
      w.write_string(server_pub)
      w.write_mpint(shared_secret)
      w.val_bytes()
    end
    SshHash.sha256(hash_input)

  fun ref _activate_encryption(s: SshStateKeyExchange, session_id: Array[U8] val) =>
    """
    Derive keys from the completed key exchange and activate per-packet
    AES-256-GCM encryption on the reader and writer.
    """
    match (s.shared_secret, s.exchange_hash)
    | (let shared: Array[U8] val, let hash: Array[U8] val) =>
      match _kex
      | let kex: SshKexStateMachine =>
        let keys = kex.derive_keys(shared, hash, session_id, s.negotiated)

        // Determine which key/IV pair to use based on role.
        // c2s = client-to-server, s2c = server-to-client.
        // Reader decrypts incoming, writer encrypts outgoing.
        (let write_key, let write_iv, let read_key, let read_iv) = match _role
        | SshRoleClient =>
          (keys.enc_key_c2s, keys.iv_c2s, keys.enc_key_s2c, keys.iv_s2c)
        | SshRoleServer =>
          (keys.enc_key_s2c, keys.iv_s2c, keys.enc_key_c2s, keys.iv_c2s)
        end

        let cipher_name = s.negotiated.cipher_c2s  // same for both directions

        if (cipher_name == "aes256-gcm@openssh.com")
          or (cipher_name == "aes128-gcm@openssh.com")
        then
          // AEAD: per-packet GCM with 12-byte IV, last 8 bytes incremented
          let write_iv_12 = recover val
            let b = Array[U8].create(12)
            var i: USize = 0
            while i < 12 do try b.push(write_iv(i)?) end; i = i + 1 end
            b
          end
          let read_iv_12 = recover val
            let b = Array[U8].create(12)
            var i: USize = 0
            while i < 12 do try b.push(read_iv(i)?) end; i = i + 1 end
            b
          end
          // Truncate key to cipher's key length (16 for aes128, 32 for aes256)
          let key_len: USize = if cipher_name == "aes128-gcm@openssh.com"
            then 16 else 32 end
          let wk = recover val
            let b = Array[U8].create(key_len)
            var i: USize = 0
            while i < key_len do try b.push(write_key(i)?) end; i = i + 1 end
            b
          end
          let rk = recover val
            let b = Array[U8].create(key_len)
            var i: USize = 0
            while i < key_len do try b.push(read_key(i)?) end; i = i + 1 end
            b
          end
          _writer.set_gcm_params(wk, write_iv_12)
          _reader.set_gcm_params(rk, read_iv_12)
        elseif (cipher_name == "aes256-ctr") or (cipher_name == "aes128-cbc") then
          // Stream cipher: persistent context + HMAC
          // IV is first 16 bytes of derived IV (AES block size)
          let write_iv_16 = recover val
            let b = Array[U8].create(16)
            var i: USize = 0
            while i < 16 do try b.push(write_iv(i)?) end; i = i + 1 end
            b
          end
          let read_iv_16 = recover val
            let b = Array[U8].create(16)
            var i: USize = 0
            while i < 16 do try b.push(read_iv(i)?) end; i = i + 1 end
            b
          end

          // MAC keys
          (let write_mac_key, let read_mac_key) = match _role
          | SshRoleClient =>
            (keys.mac_key_c2s, keys.mac_key_s2c)
          | SshRoleServer =>
            (keys.mac_key_s2c, keys.mac_key_c2s)
          end

          let mac_name = s.negotiated.mac_c2s
          let use_sha512 = mac_name == "hmac-sha2-512"
          let mac_len: USize = if use_sha512 then 64 else 32 end

          try
            let w_ctx = if cipher_name == "aes256-ctr" then
              SshCipherContext.aes_256_ctr(write_key, write_iv_16, true)?
            else
              SshCipherContext.aes_128_cbc(write_key, write_iv_16, true)?
            end
            let r_ctx = if cipher_name == "aes256-ctr" then
              SshCipherContext.aes_256_ctr(read_key, read_iv_16, false)?
            else
              SshCipherContext.aes_128_cbc(read_key, read_iv_16, false)?
            end
            _writer.set_stream_cipher(w_ctx, write_mac_key, mac_len, use_sha512)
            _reader.set_stream_cipher(r_ctx, read_mac_key, mac_len, 16, use_sha512)
          end
        end

        _encrypted = true
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
      match _role
      | SshRoleServer =>
        try
          let r = SshWireReader(payload)
          r.read_byte()?  // msg type
          let username = r.read_string_as_str()?
          let service = r.read_string_as_str()?
          let method = r.read_string_as_str()?
          let method_data: SshAuthMethodData val = match method
          | "none" => SshAuthNoneData
          | "password" =>
            r.read_bool()?  // new_password flag (ignore)
            SshAuthPasswordData(r.read_string_as_str()?)
          | "publickey" =>
            let has_sig = r.read_bool()?
            let algo = r.read_string_as_str()?
            let pk = r.read_string()?
            let sig = if has_sig then r.read_string()? else None end
            SshAuthPublicKeyData(algo, pk, sig)
          else
            SshAuthNoneData  // Unknown method treated as none
          end
          let request = SshAuthRequest(username, method, method_data)
          match _server_notify
          | let n: SshServerNotify tag => n.ssh_auth_request(this, request)
          end
        end
      end
    | SshAuthMsgTypes.userauth_pk_ok() =>
      // Server accepted our public key query. Send actual auth with signature.
      match _role
      | SshRoleClient =>
        match _auth
        | let auth_sm: SshAuthStateMachine =>
          let session_id = match _context.session_id
          | let id: Array[U8] val => id
          else recover val Array[U8] end
          end
          match auth_sm.handle_pk_ok(session_id)
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
      end
    | SshAuthMsgTypes.service_accept() =>
      // Client received service_accept, send first auth request
      match _role
      | SshRoleClient =>
        match _auth
        | let auth_sm: SshAuthStateMachine =>
          match auth_sm.next_request()
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
      end
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
        let transformed = match _channel_manager.get(recipient_channel)
        | let ch: SshChannelState =>
          match ch.pty
          | let pty: SshPtyState val => pty.transform(data)
          | None => data
          end
        | None => data
        end
        _notify_channel_data(recipient_channel, transformed)
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
    | SshChannelMsgTypes.channel_request() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let request_type = r.read_string_as_str()?
        let want_reply = r.read_bool()?
        match _server_notify
        | let n: SshServerNotify tag =>
          if request_type == "pty-req" then
            let term = r.read_string_as_str()?
            let width_chars = r.read_u32()?
            let height_rows = r.read_u32()?
            let width_pixels = r.read_u32()?
            let height_pixels = r.read_u32()?
            let mode_data = r.read_string()?
            let modes = SshTerminalModes.parse_modes(mode_data)?
            let pty = SshPtyState(term, width_chars, height_rows,
              width_pixels, height_pixels, modes)
            // Store optimistically; mark pending until accept/reject
            match _channel_manager.get(recipient_channel)
            | let ch: SshChannelState =>
              ch.pty = pty
              ch.pty_pending = true
            end
            n.ssh_pty_request(this, recipient_channel, pty, want_reply)
          elseif request_type == "shell" then
            n.ssh_shell_request(this, recipient_channel, want_reply)
          elseif request_type == "window-change" then
            let width_chars = r.read_u32()?
            let height_rows = r.read_u32()?
            let width_pixels = r.read_u32()?
            let height_pixels = r.read_u32()?
            match _channel_manager.get(recipient_channel)
            | let ch: SshChannelState =>
              match ch.pty
              | let old_pty: SshPtyState val =>
                ch.pty = SshPtyState.with_dimensions(old_pty,
                  width_chars, height_rows, width_pixels, height_pixels)
              end
            end
            n.ssh_window_change(this, recipient_channel,
              width_chars, height_rows, width_pixels, height_pixels)
          else
            n.ssh_channel_request(this, recipient_channel, request_type,
              want_reply)
          end
        end
      end
    | SshChannelMsgTypes.channel_success() => None
    | SshChannelMsgTypes.channel_failure() => None
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
    | let b: SshClientTcpBridge tag => b.write(consume packet)
    | let b: SshServerTcpBridge tag => b.write(consume packet)
    end

  fun _current_block_size(): USize =>
    """Return cipher block size, or 8 for plaintext."""
    if _encrypted then 16 else 8 end

  fun ref _disconnect_with_error(err: SshTransportError) =>
    """Send SSH_MSG_DISCONNECT and transition to Disconnected."""
    _send_packet(SshMessages.disconnect(
      SshDisconnectCodes.protocol_error(), err.string()))
    _close_bridge()
    _state = SshStateDisconnected(err)
    _notify_error(err)
    _notify_disconnected()

  fun ref _close_bridge() =>
    """Hard-close the TCP bridge to ensure immediate resource cleanup."""
    match _bridge
    | let b: SshClientTcpBridge tag => b.dispose()
    | let b: SshServerTcpBridge tag => b.dispose()
    end

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
