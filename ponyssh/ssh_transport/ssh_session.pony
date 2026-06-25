use "lori"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_auth"
use "../ssh_connection"

type _SshBridge is (SshClientTcpBridge tag | SshServerTcpBridge tag)

class val SshClientConfig
  """
  Immutable configuration for an outbound client session: the host and port to
  connect to, the username, the authentication methods to try in order, and the
  algorithm preferences (defaulting to the implemented set).
  """
  let host: String val
  let port: String val
  let username: String val
  let auth_methods: Array[SshAuthMethod val] val
  let algorithms: SshAlgorithmPreferences val

  new val create(host': String val, port': String val,
    username': String val = "",
    auth_methods': Array[SshAuthMethod val] val =
      recover val Array[SshAuthMethod val] end,
    algorithms': SshAlgorithmPreferences val =
      SshDefaultAlgorithms.preferences())
  =>
    host = host'
    port = port'
    username = username'
    auth_methods = auth_methods'
    algorithms = algorithms'

class val SshServerConfig
  """
  Immutable configuration for a server: the PEM-encoded host key, the listen
  host and port, and the algorithm preferences (defaulting to the implemented
  set). The constructor is partial — it validates the host key up front so a
  bad key fails at setup rather than at key-exchange time.
  """
  let host_key_pem: Array[U8] val
  let listen_host: String val
  let listen_port: String val
  let algorithms: SshAlgorithmPreferences val

  new val create(host_key_pem': Array[U8] val,
    listen_host': String val = "127.0.0.1",
    listen_port': String val = "22",
    algorithms': SshAlgorithmPreferences val =
      SshDefaultAlgorithms.preferences()) ?
  =>
    // Validate the host key up front. Without this an unparseable key is only
    // discovered at key-exchange time, after which the server silently drops
    // every connection. Erroring here surfaces the misconfiguration at setup.
    SshHostKeyPair.create(host_key_pem')?
    host_key_pem = host_key_pem'
    listen_host = listen_host'
    listen_port = listen_port'
    algorithms = algorithms'

actor SshSession
  """
  Owns one SSH connection: the protocol state machine, the TCP bridge, packet
  framing/crypto, key exchange (including rekey), authentication, and channel
  multiplexing. Consumers do not construct this directly — use SshConnector
  (client) or SshListener (server) — and interact with it through the tag passed
  to their SshClientNotify / SshServerNotify callbacks.
  """
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
  // The host the client was configured to connect to, passed to the host-key
  // verification callback so the consumer can bind the key to a hostname
  // (known_hosts / TOFU). Empty on the server side.
  var _remote_host: String val = ""
  // Set once teardown has begun, so the per-packet sequence-limit check does
  // not re-enter while the DISCONNECT packet is itself being sent.
  var _shutting_down: Bool = false
  // Rekey (RFC 4253 §9). _rekey holds an in-progress re-exchange while the
  // session stays Connected. From our KEXINIT until our NEWKEYS we may send
  // only key-exchange traffic, so other outgoing packets are deferred in
  // _pending_sends and flushed once our NEWKEYS is on the wire.
  // _write_baseline/_read_baseline record the sequence number at which each
  // direction's current key was installed, bounding how many packets (and thus
  // nonces) a single key sees before the next rekey.
  var _rekey: (SshRekeyContext | None) = None
  var _send_blackout: Bool = false
  // Strict key exchange (OpenSSH extension, Terrapin / CVE-2023-48795
  // mitigation). Set true once the peer's first KEXINIT advertises the marker
  // (we always advertise ours, so this means both sides do). While true the
  // packet sequence number is reset to zero at every NEWKEYS, and during the
  // initial key exchange only key-exchange packets are tolerated.
  var _strict_kex: Bool = false
  let _pending_sends: Array[Array[U8] val] = Array[Array[U8] val]
  var _write_baseline: U32 = 0
  var _read_baseline: U32 = 0
  // Set the first time the session enters its terminal state, so teardown runs
  // once: the consumer sees a single ssh_disconnected and no duplicate
  // DISCONNECT is sent into an already-closed bridge.
  var _terminated: Bool = false

  let _version_string: String val = "SSH-2.0-ponyssh_0.1"

  // --- Factory constructors ---

  new create_client(auth: TCPConnectAuth, config: SshClientConfig val,
    notify: SshClientNotify tag)
  =>
    _role = SshRoleClient
    _client_notify = notify
    _server_notify = None
    _prefs = config.algorithms
    _kex = SshKexStateMachine(SshRoleClient)
    _auth = SshAuthStateMachine(config.username, config.auth_methods)
    _remote_host = config.host
    _bridge = SshClientTcpBridge(auth, config.host, config.port, this)

  new create_server(config: SshServerConfig val, notify: SshServerNotify tag) =>
    _role = SshRoleServer
    _client_notify = None
    _server_notify = notify
    _prefs = config.algorithms
    _kex = SshKexStateMachine(SshRoleServer)
    _auth = None
    try _host_key = SshHostKeyPair.create(config.host_key_pem)? end
    // The server bridge is wired immediately after construction by SshListener
    // via set_server_bridge (the bridge needs the session as its notify target,
    // so the session must exist first).

  be set_server_bridge(bridge: SshServerTcpBridge tag) =>
    """
    Wire the TCP bridge for a server session. Accepted only once, right after
    construction; a later call (e.g. from consumer code) cannot replace the
    bridge of a live session.
    """
    match _bridge
    | None => _bridge = bridge
    end

  // --- Public behaviors (called by consumers) ---

  be open_channel(channel_type: String val = "session") =>
    match _state
    | let _: SshStateConnected =>
      let local_id = _channel_manager.open_channel(channel_type)
      _send_packet(SshChannelMessages.channel_open(channel_type, local_id,
        SshChannelWindow.initial(), 0x8000))
    end

  be channel_send(channel_id: U32, data: Array[U8] val) =>
    match _state
    | let _: SshStateConnected => _channel_send_segmented(channel_id, data)
    end

  fun ref _channel_send_segmented(channel_id: U32, data: Array[U8] val) =>
    """
    Split outbound channel data into packets no larger than the peer's
    advertised max_packet_size (and no larger than its remaining send window),
    rather than emitting one oversized CHANNEL_DATA a conformant peer rejects.
    """
    let max_packet = match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        let m = ch.max_packet_size.usize()
        if m == 0 then 32768 else m end
      | None =>
        _notify_channel_error(channel_id, SshChannelClosed)
        return
      end
    var offset: USize = 0
    while offset < data.size() do
      let window = match _channel_manager.get(channel_id)
        | let ch: SshChannelState => ch.remote_window.usize()
        | None =>
          _notify_channel_error(channel_id, SshChannelClosed)
          return
        end
      if window == 0 then
        // The peer's send window is exhausted; the remainder cannot go out
        // until it grants more via CHANNEL_WINDOW_ADJUST.
        _notify_channel_error(channel_id, SshWindowExhausted)
        return
      end
      let seg_len = (data.size() - offset).min(max_packet).min(window)
      let segment = recover val
        let b = Array[U8].create(seg_len)
        b.copy_from(data, offset, 0, seg_len)
        b
      end
      match _channel_manager.channel_data_send(channel_id, seg_len)
      | let remote_id: U32 =>
        _send_packet(SshChannelMessages.channel_data(remote_id, segment))
      | let err: SshChannelError =>
        _notify_channel_error(channel_id, err)
        return
      end
      offset = offset + seg_len
    end

  be channel_request_shell(channel_id: U32, want_reply: Bool = true) =>
    """
    Ask the peer to start a login shell on a channel we opened (RFC 4254 §6.5).
    The channel's output arrives via ssh_channel_data. A no-op unless the
    session is Connected and the channel exists.
    """
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        _send_packet(SshChannelMessages.channel_request_shell(
          ch.remote_id, want_reply))
      end
    end

  be channel_request_exec(channel_id: U32, command: String val,
    want_reply: Bool = true)
  =>
    """
    Ask the peer to run a single command on a channel we opened (RFC 4254 §6.5).
    The command's output arrives via ssh_channel_data. A no-op unless the
    session is Connected and the channel exists.
    """
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        _send_packet(SshChannelMessages.channel_request_exec(
          ch.remote_id, command, want_reply))
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
    // The consumer has approved the server's host key. Clear the gate; if the
    // server's NEWKEYS has already arrived (auth was held pending approval),
    // begin authentication now. Encryption was activated when NEWKEYS arrived.
    match _state
    | let s: SshStateKeyExchange =>
      s.awaiting_host_key_verification = false
      if s.server_newkeys_received then
        _begin_authentication()
      end
    end

  be reject_host_key() =>
    // The consumer rejected the server's host key. Tear down before any
    // credentials are sent.
    _disconnect_with_error(SshKexFailed(SshKeyInvalid))

  be disconnect(msg: String val = "") =>
    """Clean disconnect initiated by consumer."""
    if _terminated then return end
    _terminated = true
    _send_packet(SshMessages.disconnect(
      SshDisconnectCodes.by_application(), msg))
    _close_bridge()
    _state = SshStateDisconnected(None)
    _notify_disconnected()

  be rekey() =>
    """
    Request a key re-exchange. A no-op unless the session is Connected and no
    rekey is already in progress. The session also rekeys automatically as the
    per-key packet count grows, so consumers rarely need this.
    """
    _start_rekey()

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
          ch.remote_id, ch.local_id, SshChannelWindow.initial(), 0x8000))
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
    if _terminated then return end
    _terminated = true
    _state = SshStateDisconnected(SshConnectionLost)
    _notify_disconnected()

  be _tcp_connection_failed() =>
    if _terminated then return end
    _terminated = true
    _state = SshStateDisconnected(SshConnectionLost)
    _notify_error(SshConnectionLost)
    _notify_disconnected()

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
      | let payload: Array[U8] val =>
        _dispatch_packet(payload)
        // Bound per-key packet/nonce counts (rekey or, as a backstop, tear
        // down) before the sequence number approaches the 2^32 nonce wrap.
        if _check_packet_limits() then return end
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
            // The first KEXINIT advertises the strict-KEX marker; rekey
            // KEXINITs must not (the marker is only valid in the first).
            let our_kexinit =
              try kex.generate_kexinit(_prefs where include_strict_marker = true)?
              else
                _disconnect_with_error(SshKexFailed(SshKeyInvalid))
                return
              end
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
        // Bound the pre-handshake buffer. RFC 4253 caps the version line at
        // 255 bytes; we allow generous room for optional preceding banner
        // lines. Without this an unauthenticated peer that never sends a line
        // terminator could grow the buffer without bound (memory DoS).
        if _reader.buffered_size() > _max_version_exchange_bytes() then
          _disconnect_with_error(SshProtocolVersionMismatch)
        end
        return  // Not enough data yet
      end
    end

  fun _max_version_exchange_bytes(): USize => 8192

  fun ref _dispatch_packet(payload: Array[U8] val) =>
    """Route a decrypted payload to the appropriate handler based on state."""
    try
      let msg_type = payload(0)?

      // Strict KEX (Terrapin / CVE-2023-48795): during the initial key exchange
      // the only legal packets are key-exchange messages. Anything else — even
      // IGNORE/DEBUG/UNIMPLEMENTED, which are otherwise always allowed — is an
      // injection attempt that desynchronises the transcript; tear down. A peer
      // DISCONNECT is still honoured below. Enforced only once we know the peer
      // also negotiated strict KEX, and only until the first NEWKEYS brings
      // encryption up (after which EXT_INFO and the like are legitimate).
      if _strict_kex and (not _encrypted)
        and (not _is_kex_message(msg_type))
        and (msg_type != SshMsgTypes.disconnect())
      then
        _disconnect_with_error(SshStrictKexViolation)
        return
      end

      // Global messages handled in any state (RFC 4253 §11)
      match msg_type
      | SshMsgTypes.disconnect() =>
        _peer_disconnected()
        return
      | SshMsgTypes.ignore() => return    // silently discard
      | SshMsgTypes.debug() => return     // silently discard
      | SshMsgTypes.unimplemented() => return  // peer couldn't handle something
      | SshMsgTypes.ext_info() => return  // extensions info, safe to ignore
      end

      // Rekey (RFC 4253 §9). Once connected, key-exchange traffic drives a
      // re-exchange rather than the session state machine. A KEXINIT with no
      // rekey yet in progress is the peer initiating one; we start ours and
      // process theirs. Subsequent KEX messages route to the active rekey.
      if _is_kex_message(msg_type) then
        match _rekey
        | let rk: SshRekeyContext => _handle_rekey(rk, msg_type, payload); return
        | None =>
          match _state
          | let _: SshStateConnected =>
            if msg_type == SshMsgTypes.kexinit() then
              match _start_rekey()
              | let rk: SshRekeyContext => _handle_rekey(rk, msg_type, payload)
              end
              return
            end
          end
        end
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
          // Strict KEX is in effect iff the peer also advertised the marker in
          // this (first) KEXINIT. Detected once, here, during the initial KEX.
          _strict_kex = SshStrictKex.peer_advertised(payload, _role)
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
      // Strict KEX: our incoming sequence number resets to zero at the peer's
      // NEWKEYS (the NEWKEYS packet itself has already been counted), so the
      // first packet under the new key is parsed at sequence 0. Done before
      // _activate_encryption so the reader's per-key baseline starts at 0.
      if _strict_kex then _reader.reset_sequence_number() end
      let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else
        recover val Array[U8] end
      end
      // Activate encryption using stored key exchange results. Only advance to
      // authentication once a cipher is actually installed; on failure
      // _activate_encryption has already torn the connection down.
      match _state
      | let kex_s: SshStateKeyExchange =>
        if _activate_encryption(kex_s, session_id) then
          // A client must not begin authentication — which puts its
          // credentials on the wire — until the consumer has approved the
          // server's host key. If approval is still pending, hold here;
          // accept_host_key() resumes via _begin_authentication.
          if kex_s.awaiting_host_key_verification then
            kex_s.server_newkeys_received = true
          else
            _begin_authentication()
          end
        end
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
            host_key_blob, client_pub, server_pub, shared_secret)?

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
            // Strict KEX: our outgoing sequence number resets to zero at our
            // NEWKEYS, so the first packet under the new key is sequence 0.
            if _strict_kex then _writer.reset_sequence_number() end
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
        // Parse host key blob to get SshHostKey
        try
          let exchange_hash = _compute_exchange_hash(
            client_version, server_version,
            s.our_kexinit, s.their_kexinit,
            host_key_blob, client_pub, server_pub, shared_secret)?

          // Set session_id
          if _context.session_id is None then
            _context.session_id = exchange_hash
          end

          // Store shared secret and exchange hash for key derivation after NEWKEYS
          s.shared_secret = shared_secret
          s.exchange_hash = exchange_hash

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
            // Strict KEX: our outgoing sequence number resets to zero at our
            // NEWKEYS, so the first packet under the new key is sequence 0.
            if _strict_kex then _writer.reset_sequence_number() end
            // Notify consumer for host key verification (accept/reject
            // controls whether auth proceeds after we receive server NEWKEYS)
            s.awaiting_host_key_verification = true
            match _client_notify
            | let n: SshClientNotify tag =>
              n.ssh_verify_host_key(this, _remote_host, host_key)
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

  fun _is_kex_message(msg_type: U8): Bool =>
    (msg_type == SshMsgTypes.kexinit())
      or (msg_type == SshMsgTypes.kex_ecdh_init())
      or (msg_type == SshMsgTypes.kex_ecdh_reply())
      or (msg_type == SshMsgTypes.newkeys())

  fun ref _start_rekey(): (SshRekeyContext | None) =>
    """
    Begin a key re-exchange, or return the one already in progress. Sends our
    KEXINIT and enters the send-blackout. Only meaningful once Connected.
    """
    match _rekey
    | let r: SshRekeyContext => return r
    end
    match _state
    | let _: SshStateConnected => None
    else
      return None
    end
    match _kex
    | let kex: SshKexStateMachine =>
      let ki =
        try kex.generate_kexinit(_prefs)?
        else
          _disconnect_with_error(SshKexFailed(SshKeyInvalid))
          return None
        end
      let rk = SshRekeyContext(ki)
      _rekey = rk
      // From our KEXINIT until our NEWKEYS we may send only key-exchange
      // traffic (RFC 4253 §9); defer everything else until the blackout ends.
      _send_blackout = true
      _send_kex_packet(ki)
      rk
    else
      None
    end

  fun ref _handle_rekey(rk: SshRekeyContext, msg_type: U8,
    payload: Array[U8] val)
  =>
    """Route a key-exchange message belonging to an in-progress rekey."""
    match msg_type
    | SshMsgTypes.kexinit() =>
      // Negotiate from the peer's KEXINIT and, as client, drive ECDH. A second
      // KEXINIT is ignored.
      match rk.their_kexinit
      | None =>
        match _kex
        | let kex: SshKexStateMachine =>
          match kex.receive_kexinit(payload, _prefs)
          | let neg: SshNegotiatedAlgorithms val =>
            rk.their_kexinit = payload
            rk.negotiated = neg
            match _role
            | SshRoleClient =>
              try
                let ck = SshKexCurve25519.create()?
                rk.our_kex = ck
                _send_kex_packet(SshMessages.kex_ecdh_init(ck.public_key()))
              else
                _disconnect_with_error(SshKexFailed(SshKeyInvalid))
              end
            end
          | let err: SshTransportError =>
            _disconnect_with_error(err)
          end
        end
      end
    | SshMsgTypes.kex_ecdh_init() =>
      match _role
      | SshRoleServer => _rekey_server_ecdh(rk, payload)
      end
    | SshMsgTypes.kex_ecdh_reply() =>
      match _role
      | SshRoleClient => _rekey_client_ecdh(rk, payload)
      end
    | SshMsgTypes.newkeys() =>
      _rekey_recv_newkeys(rk)
    end

  fun ref _rekey_server_ecdh(rk: SshRekeyContext, payload: Array[U8] val) =>
    """
    Server side of a rekey: derive the new shared secret and keys, sign the new
    exchange hash (bound to the unchanged session id), and send KEX_ECDH_REPLY
    followed by NEWKEYS.
    """
    (let neg: SshNegotiatedAlgorithms val, let their_ki: Array[U8] val) =
      match (rk.negotiated, rk.their_kexinit)
      | (let n: SshNegotiatedAlgorithms val, let tk: Array[U8] val) => (n, tk)
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        return
      end
    let kex = match _kex
      | let k: SshKexStateMachine => k
      else _disconnect_with_error(SshKexFailed(SshKeyInvalid)); return
      end
    let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else _disconnect_with_error(SshKexFailed(SshKeyInvalid)); return
      end
    try
      let r = SshWireReader(payload)
      r.read_byte()?  // msg type
      let client_pub = r.read_string()?
      let server_kex = SshKexCurve25519.create()?
      let server_pub = server_kex.public_key()
      match server_kex.derive_shared_secret(client_pub)
      | let shared: Array[U8] val =>
        match _host_key
        | let hk: SshHostKeyPair =>
          let pub_key = hk.public_key()
          let host_key_blob = recover val
            let w = SshWireWriter
            w.write_string_from_str(pub_key.algorithm)
            w.write_string(pub_key.public_key_data)
            w.val_bytes()
          end
          let client_version = match _context.remote_version
            | let v: String val => v else "" end
          let exchange_hash = _compute_exchange_hash(client_version,
            _version_string, their_ki, rk.our_kexinit, host_key_blob,
            client_pub, server_pub, shared)?
          // The session id never changes; the new keys bind to the original.
          let keys = kex.derive_keys(shared, exchange_hash, session_id, neg)?
          match hk.sign(exchange_hash)
          | let raw_sig: Array[U8] val =>
            let sig_blob = recover val
              let w = SshWireWriter
              w.write_string_from_str(pub_key.algorithm)
              w.write_string(raw_sig)
              w.val_bytes()
            end
            _send_kex_packet(SshMessages.kex_ecdh_reply(host_key_blob,
              server_pub, sig_blob))
            rk.derived = keys
            _rekey_send_newkeys(rk)
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

  fun ref _rekey_client_ecdh(rk: SshRekeyContext, payload: Array[U8] val) =>
    """
    Client side of a rekey: verify the server presents the same host key and a
    valid signature over the new exchange hash, derive the new keys, and send
    NEWKEYS. The consumer is not re-prompted — the key was approved already.
    """
    (let neg: SshNegotiatedAlgorithms val, let their_ki: Array[U8] val) =
      match (rk.negotiated, rk.their_kexinit)
      | (let n: SshNegotiatedAlgorithms val, let tk: Array[U8] val) => (n, tk)
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        return
      end
    let client_kex = match rk.our_kex
      | let k: SshKexCurve25519 => k
      else _disconnect_with_error(SshKexFailed(SshKeyInvalid)); return
      end
    let kex = match _kex
      | let k: SshKexStateMachine => k
      else _disconnect_with_error(SshKexFailed(SshKeyInvalid)); return
      end
    let session_id = match _context.session_id
      | let id: Array[U8] val => id
      else _disconnect_with_error(SshKexFailed(SshKeyInvalid)); return
      end
    try
      let r = SshWireReader(payload)
      r.read_byte()?  // msg type
      let host_key_blob = r.read_string()?
      let server_pub = r.read_string()?
      let signature = r.read_string()?
      let client_pub = client_kex.public_key()
      match client_kex.derive_shared_secret(server_pub)
      | let shared: Array[U8] val =>
        let server_version = match _context.remote_version
          | let v: String val => v else "" end
        let exchange_hash = _compute_exchange_hash(_version_string,
          server_version, rk.our_kexinit, their_ki, host_key_blob, client_pub,
          server_pub, shared)?
        let kr = SshWireReader(host_key_blob)
        let algo = kr.read_string_as_str()?
        let pk_data = kr.read_string()?
        let host_key = SshHostKey(algo, pk_data)
        // The server must present the same host key it did at the initial
        // exchange; a change at rekey would be a MITM swapping identities.
        match _context.server_host_key
        | let prev: SshHostKey val =>
          if not _same_host_key(prev, host_key) then
            _disconnect_with_error(SshKexFailed(SshKeyInvalid))
            return
          end
        end
        let sr = SshWireReader(signature)
        sr.read_string_as_str()?  // signature algorithm
        let raw_sig = sr.read_string()?
        match SshHostKeyVerify.verify(host_key, raw_sig, exchange_hash)
        | true =>
          let keys = kex.derive_keys(shared, exchange_hash, session_id, neg)?
          rk.derived = keys
          _rekey_send_newkeys(rk)
        | let err: SshCryptoError =>
          _disconnect_with_error(SshKexFailed(err))
        end
      | let err: SshCryptoError =>
        _disconnect_with_error(SshKexFailed(err))
      end
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
    end

  fun _same_host_key(a: SshHostKey val, b: SshHostKey val): Bool =>
    if a.algorithm != b.algorithm then return false end
    if a.public_key_data.size() != b.public_key_data.size() then return false end
    var i: USize = 0
    while i < a.public_key_data.size() do
      if (try a.public_key_data(i)? else return false end)
        != (try b.public_key_data(i)? else return false end)
      then
        return false
      end
      i = i + 1
    end
    true

  fun ref _rekey_send_newkeys(rk: SshRekeyContext) =>
    """
    Send our NEWKEYS (under the old key), switch our outgoing direction to the
    new key, and end the send-blackout — flushing any deferred packets.
    """
    _send_kex_packet(SshMessages.newkeys())
    // Strict KEX persists for the connection: reset our outgoing sequence
    // number at every NEWKEYS, so _install_writer baselines this key at 0.
    if _strict_kex then _writer.reset_sequence_number() end
    match (rk.derived, rk.negotiated)
    | (let keys: SshDerivedKeys val, let neg: SshNegotiatedAlgorithms val) =>
      if not _install_writer(keys, neg) then return end
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
      return
    end
    rk.sent_newkeys = true
    _send_blackout = false
    _flush_pending_sends()
    _maybe_finish_rekey(rk)

  fun ref _rekey_recv_newkeys(rk: SshRekeyContext) =>
    """Peer NEWKEYS received: switch our incoming direction to the new key."""
    // Strict KEX persists for the connection: reset our incoming sequence
    // number at every NEWKEYS, so _install_reader baselines this key at 0.
    if _strict_kex then _reader.reset_sequence_number() end
    match (rk.derived, rk.negotiated)
    | (let keys: SshDerivedKeys val, let neg: SshNegotiatedAlgorithms val) =>
      if not _install_reader(keys, neg) then return end
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
      return
    end
    rk.recv_newkeys = true
    _maybe_finish_rekey(rk)

  fun ref _maybe_finish_rekey(rk: SshRekeyContext) =>
    """Once both directions have switched to the new keys, the rekey is done."""
    if rk.sent_newkeys and rk.recv_newkeys then
      _rekey = None
    end

  fun _compute_exchange_hash(
    client_version: String val, server_version: String val,
    client_kexinit: Array[U8] val, server_kexinit: Array[U8] val,
    host_key_blob: Array[U8] val,
    client_pub: Array[U8] val, server_pub: Array[U8] val,
    shared_secret: Array[U8] val): Array[U8] val ?
  =>
    """
    Compute the full exchange hash per RFC 4253 section 8 / RFC 8731:
    H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
              || string(K_S) || string(Q_C) || string(Q_S) || mpint(K))
    Errors if the SHA-256 computation fails.
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
    SshHash.sha256(hash_input)?

  fun ref _activate_encryption(s: SshStateKeyExchange, session_id: Array[U8] val):
    Bool
  =>
    """
    Derive keys from the completed key exchange and activate the negotiated
    cipher on the reader and writer. Returns true once a cipher is installed.
    Returns false — after tearing the connection down — when key material is
    missing or the negotiated cipher is unsupported, so the session is never
    marked encrypted without a cipher actually in place.
    """
    (let shared: Array[U8] val, let hash: Array[U8] val) =
      match (s.shared_secret, s.exchange_hash)
      | (let sh: Array[U8] val, let h: Array[U8] val) => (sh, h)
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        return false
      end

    let kex = match _kex
    | let k: SshKexStateMachine => k
    else
      _disconnect_with_error(SshKexFailed(SshKeyInvalid))
      return false
    end

    let keys =
      try
        kex.derive_keys(shared, hash, session_id, s.negotiated)?
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        return false
      end

    // Install both directions at once for the initial handshake (no encrypted
    // data flows before NEWKEYS, so the directional timing is moot here). Rekey
    // installs each direction separately at its own NEWKEYS boundary.
    if not _install_writer(keys, s.negotiated) then return false end
    if not _install_reader(keys, s.negotiated) then return false end

    _encrypted = true
    true

  fun ref _install_writer(keys: SshDerivedKeys val,
    neg: SshNegotiatedAlgorithms val): Bool
  =>
    """Configure the writer for our outgoing direction from derived key data."""
    // The writer encrypts our outgoing direction: c2s for a client, s2c for a
    // server. SSH negotiates the cipher/MAC for each direction independently.
    (let cipher: String val, let mac: String val) =
      match _role
      | SshRoleClient => (neg.cipher_c2s, neg.mac_c2s)
      | SshRoleServer => (neg.cipher_s2c, neg.mac_s2c)
      end
    (let key: Array[U8] val, let iv: Array[U8] val, let mac_key: Array[U8] val) =
      match _role
      | SshRoleClient => (keys.enc_key_c2s, keys.iv_c2s, keys.mac_key_c2s)
      | SshRoleServer => (keys.enc_key_s2c, keys.iv_s2c, keys.mac_key_s2c)
      end
    if _install_write_cipher(cipher, mac, key, iv, mac_key) then
      // Baseline the per-key packet count for this direction. For chacha the
      // nonce is the sequence number, so this bounds how many nonces a single
      // key sees before the next rekey.
      _write_baseline = _writer.sequence_number()
      true
    else
      false
    end

  fun ref _install_reader(keys: SshDerivedKeys val,
    neg: SshNegotiatedAlgorithms val): Bool
  =>
    """Configure the reader for the peer's incoming direction."""
    (let cipher: String val, let mac: String val) =
      match _role
      | SshRoleClient => (neg.cipher_s2c, neg.mac_s2c)
      | SshRoleServer => (neg.cipher_c2s, neg.mac_c2s)
      end
    (let key: Array[U8] val, let iv: Array[U8] val, let mac_key: Array[U8] val) =
      match _role
      | SshRoleClient => (keys.enc_key_s2c, keys.iv_s2c, keys.mac_key_s2c)
      | SshRoleServer => (keys.enc_key_c2s, keys.iv_c2s, keys.mac_key_c2s)
      end
    if _install_read_cipher(cipher, mac, key, iv, mac_key) then
      _read_baseline = _reader.sequence_number()
      true
    else
      false
    end

  fun ref _install_write_cipher(cipher_name: String val, mac_name: String val,
    key: Array[U8] val, iv: Array[U8] val, mac_key: Array[U8] val): Bool
  =>
    """
    Configure the packet writer for our outgoing direction. Returns true once a
    cipher is installed; on failure tears the connection down and returns false.
    """
    if cipher_name == "chacha20-poly1305@openssh.com" then
      // 64 bytes of key material: main_key(32) || header_key(32). No separate
      // IV or MAC key — poly1305 is the MAC, the nonce is the sequence number.
      try
        _writer.set_chacha20_poly1305(
          SshChacha20Poly1305Context(_first_bytes(key, 64))?)
        true
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        false
      end
    elseif (cipher_name == "aes256-gcm@openssh.com")
      or (cipher_name == "aes128-gcm@openssh.com")
    then
      let key_len: USize =
        if cipher_name == "aes128-gcm@openssh.com" then 16 else 32 end
      _writer.set_gcm_params(_first_bytes(key, key_len), _first_bytes(iv, 12))
      true
    elseif cipher_name == "aes256-ctr" then
      let use_sha512 = mac_name == "hmac-sha2-512"
      let mac_len: USize = if use_sha512 then 64 else 32 end
      try
        let ctx = SshCipherContext.aes_256_ctr(key, _first_bytes(iv, 16), true)?
        _writer.set_stream_cipher(ctx, _first_bytes(mac_key, mac_len), mac_len,
          use_sha512)
        true
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        false
      end
    else
      // Negotiated a cipher the transport cannot apply. Fail closed rather
      // than fall through and send plaintext on a session marked encrypted.
      _disconnect_with_error(SshAlgorithmNegotiationFailed)
      false
    end

  fun ref _install_read_cipher(cipher_name: String val, mac_name: String val,
    key: Array[U8] val, iv: Array[U8] val, mac_key: Array[U8] val): Bool
  =>
    """
    Configure the packet reader for the peer's incoming direction. Returns true
    once a cipher is installed; on failure tears the connection down.
    """
    if cipher_name == "chacha20-poly1305@openssh.com" then
      try
        _reader.set_chacha20_poly1305(
          SshChacha20Poly1305Context(_first_bytes(key, 64))?)
        true
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        false
      end
    elseif (cipher_name == "aes256-gcm@openssh.com")
      or (cipher_name == "aes128-gcm@openssh.com")
    then
      let key_len: USize =
        if cipher_name == "aes128-gcm@openssh.com" then 16 else 32 end
      _reader.set_gcm_params(_first_bytes(key, key_len), _first_bytes(iv, 12))
      true
    elseif cipher_name == "aes256-ctr" then
      let use_sha512 = mac_name == "hmac-sha2-512"
      let mac_len: USize = if use_sha512 then 64 else 32 end
      try
        let ctx = SshCipherContext.aes_256_ctr(key, _first_bytes(iv, 16), false)?
        _reader.set_stream_cipher(ctx, _first_bytes(mac_key, mac_len), mac_len,
          16, use_sha512)
        true
      else
        _disconnect_with_error(SshKexFailed(SshKeyInvalid))
        false
      end
    else
      _disconnect_with_error(SshAlgorithmNegotiationFailed)
      false
    end

  fun _first_bytes(src: Array[U8] val, n: USize): Array[U8] val =>
    """
    Return a copy of the first n bytes of src. src is expected to hold at
    least n bytes; a shorter src yields a shorter result, which downstream
    construction (e.g. the chacha context) rejects.
    """
    recover val
      let b = Array[U8].create(n)
      var i: USize = 0
      while i < n do
        try b.push(src(i)?) end
        i = i + 1
      end
      b
    end

  fun ref _handle_auth(msg_type: U8, payload: Array[U8] val) =>
    """Handle messages during authentication."""
    match msg_type
    | SshAuthMsgTypes.userauth_success() =>
      // Only a client acts on USERAUTH_SUCCESS. A server that receives this
      // message has authenticated nothing; acting on it would let a client
      // jump straight to Connected, bypassing authentication entirely.
      match _role
      | SshRoleClient =>
        let session_id = match _context.session_id
        | let id: Array[U8] val => id
        else
          recover val Array[U8] end
        end
        _state = SshStateConnected(session_id)
        match _client_notify
        | let n: SshClientNotify tag => n.ssh_ready(this)
        end
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
          // RFC 4252: a userauth request targets the "ssh-connection" service.
          // Enforce it so the service value bound into a publickey signature is
          // fixed rather than attacker-chosen.
          if service != "ssh-connection" then
            _send_packet(SshAuthMessages.userauth_failure(
              ["publickey"; "password"], false))
            return
          end
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
          // For a signed publickey request, prove possession of the private
          // key before consulting the consumer. An invalid signature is
          // rejected here, so the consumer is only ever asked to authorize a
          // key whose ownership has been cryptographically established.
          match method_data
          | let pkd: SshAuthPublicKeyData val =>
            match pkd.signature
            | let _: Array[U8] val =>
              if not _verify_publickey_signature(username, service, pkd) then
                _send_packet(SshAuthMessages.userauth_failure(
                  ["publickey"; "password"], false))
                return
              end
            end
          end

          let request = SshAuthRequest(username, method, method_data)
          match _server_notify
          | let n: SshServerNotify tag => n.ssh_auth_request(this, request)
          end
        else
          // A malformed/truncated auth request is a protocol violation; tear
          // down rather than silently drop it and leave the peer waiting.
          _disconnect_with_error(SshPacketCorrupt)
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
        match _server_notify
        | let n: SshServerNotify tag =>
          // Cap the number of concurrent channels before allocating state. A
          // peer flooding CHANNEL_OPEN would otherwise grow _channels without
          // bound (each entry advertises a 2 MiB window) — a memory DoS.
          // RFC 4254 §5.1 reason 4 = SSH_OPEN_RESOURCE_SHORTAGE.
          if _channel_manager.at_capacity() then
            _send_packet(SshChannelMessages.channel_open_failure(
              sender_channel, 4, "too many open channels"))
          else
            let local_id = _channel_manager.accept_channel(
              0, sender_channel, initial_window, max_packet, ch_type)
            n.ssh_channel_open_request(this, local_id, ch_type)
          end
        | None =>
          // A client never accepts inbound channels. Reject without allocating
          // state: there is no client-side authorization callback, so an
          // accepted channel would be orphaned and never removable — a memory
          // DoS driven by a malicious server. RFC 4254 §5.1 reason 1 =
          // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.
          _send_packet(SshChannelMessages.channel_open_failure(
            sender_channel, 1, "channels not accepted"))
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
        // recipient_channel must name a channel we actually opened.
        if _channel_manager.get(recipient_channel) is None then error end
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
        if _channel_manager.get(recipient_channel) is None then error end
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
        // Drop data for a channel we never opened. recipient_channel is
        // attacker-controlled; without this a peer can inject data on, and
        // surface to the consumer, channel ids that never existed.
        let ch = match _channel_manager.get(recipient_channel)
          | let c: SshChannelState => c
          | None => error
          end
        // Enforce the receive window we advertised. A peer that overruns it is
        // violating flow control; close the channel rather than deliver
        // unbounded data.
        match _channel_manager.channel_data_received(recipient_channel,
          data.size())
        | let _: SshChannelError =>
          _send_packet(SshChannelMessages.channel_close(ch.remote_id))
          _channel_manager.close_channel(recipient_channel)
          _notify_channel_error(recipient_channel, SshWindowExhausted)
        | let _: U32 =>
          let transformed = match ch.pty
            | let pty: SshPtyState val => pty.transform(data)
            | None => data
            end
          _notify_channel_data(recipient_channel, transformed)
          // Replenish the receive window so the peer can keep sending; data
          // handed to the consumer is treated as consumed.
          match _channel_manager.replenish_local_window(recipient_channel)
          | let inc: U32 =>
            _send_packet(SshChannelMessages.channel_window_adjust(
              ch.remote_id, inc))
          end
        end
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
        if _channel_manager.get(recipient_channel) is None then error end
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
        if _channel_manager.get(recipient_channel) is None then error end
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
    | SshMsgTypes.disconnect() =>
      _peer_disconnected()
    end

  fun ref _send_packet(payload: Array[U8] val) =>
    """
    Frame and send a packet. While a rekey is in its send-blackout (from our
    KEXINIT to our NEWKEYS) non-key-exchange packets are deferred so we emit
    only key-exchange traffic, as RFC 4253 §9 requires.
    """
    if _send_blackout then
      _pending_sends.push(payload)
      return
    end
    _frame_and_send(payload)
    _check_packet_limits()

  fun ref _send_kex_packet(payload: Array[U8] val) =>
    """Send a key-exchange/transport packet, bypassing the rekey send-blackout."""
    _frame_and_send(payload)

  fun ref _frame_and_send(payload: Array[U8] val) =>
    let block_size: USize = _current_block_size()
    let packet = _writer.write(payload, block_size)
    match _bridge
    | let b: SshClientTcpBridge tag => b.write(consume packet)
    | let b: SshServerTcpBridge tag => b.write(consume packet)
    end

  fun ref _flush_pending_sends() =>
    """Send packets deferred during the rekey send-blackout, in order."""
    while _pending_sends.size() > 0 do
      try _frame_and_send(_pending_sends.shift()?) end
    end

  fun _rekey_packet_limit(): U32 => 0x4000_0000  // 2^30: initiate rekey
  fun _hard_packet_limit(): U32 => 0x7000_0000   // backstop, well under 2^31

  fun _packets_since_rekey(): U32 =>
    """
    The larger of the two directions' packet counts since their current key was
    installed. U32 subtraction is modular, so this stays correct across a
    sequence-number wrap as long as the true distance is below 2^32 (it is — we
    rekey every 2^30).
    """
    (_writer.sequence_number() - _write_baseline)
      .max(_reader.sequence_number() - _read_baseline)

  fun ref _check_packet_limits(): Bool =>
    """
    Keep each key's packet (and thus nonce) count bounded. Initiate a rekey at
    2^30 packets so the session can continue indefinitely; as a backstop, if a
    rekey never completes, fail closed well before the 2^32 nonce wrap. Returns
    true once teardown has been initiated.
    """
    if _shutting_down then return false end
    let since = _packets_since_rekey()
    if since >= _hard_packet_limit() then
      _shutting_down = true
      _disconnect_with_error(SshRekeyUnsupported)
      return true
    end
    if (since >= _rekey_packet_limit()) and (_rekey is None) then
      _start_rekey()
    end
    false

  fun _current_block_size(): USize =>
    """Return cipher block size, or 8 for plaintext."""
    if _encrypted then 16 else 8 end

  fun ref _disconnect_with_error(err: SshTransportError) =>
    """Send SSH_MSG_DISCONNECT and transition to Disconnected."""
    if _terminated then return end
    _terminated = true
    _send_packet(SshMessages.disconnect(
      SshDisconnectCodes.protocol_error(), err.string()))
    _close_bridge()
    _state = SshStateDisconnected(err)
    _notify_error(err)
    _notify_disconnected()

  fun ref _peer_disconnected() =>
    """React once to a peer-initiated DISCONNECT message."""
    if _terminated then return end
    _terminated = true
    _state = SshStateDisconnected(SshConnectionLost)
    _notify_disconnected()

  fun ref _close_bridge() =>
    """Hard-close the TCP bridge to ensure immediate resource cleanup."""
    match _bridge
    | let b: SshClientTcpBridge tag => b.dispose()
    | let b: SshServerTcpBridge tag => b.dispose()
    end

  fun ref _begin_authentication() =>
    """
    Transition to the authentication phase. Called once encryption is active
    and, on a client, the server's host key has been approved. A client kicks
    off authentication by requesting the ssh-userauth service; a server waits
    for the client to do so.
    """
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

  fun _verify_publickey_signature(username: String val, service: String val,
    pk: SshAuthPublicKeyData val): Bool
  =>
    """
    Verify a publickey userauth signature against the established session id.
    Delegates to SshPublicKeyVerifier; without a session id (which is always
    set by the time auth runs) verification fails closed.
    """
    match _context.session_id
    | let id: Array[U8] val =>
      SshPublicKeyVerifier.verify(id, username, service, pk)
    else
      false
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
