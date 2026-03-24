use "encode/base64"
use "lori"
use "buffered"
use "../../ponyssh/ssh_transport"
use "../../ponyssh/ssh_crypto"
use "../../ponyssh/ssh_error"
use "../../ponyssh/ssh_auth"
use "../../ponyssh/ssh_connection"
use "../../ponyssh/ssh_server"

actor Main
  new create(env: Env) =>
    env.out.print("SSH Echo Server starting on port 2222...")

    let pem: Array[U8] val = _EchoServerKey()
    let ciphers = recover val
      let a = Array[String val]
      a.push("aes256-gcm@openssh.com")
      a.push("aes128-gcm@openssh.com")
      a.push("aes256-ctr")
      a.push("aes128-cbc")
      a
    end
    let prefs = SshAlgorithmPreferences(
      recover val let a = Array[String val]; a.push("curve25519-sha256"); a end,
      recover val let a = Array[String val]; a.push("ssh-ed25519"); a end,
      ciphers, ciphers,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end)
    let config = SshServerConfig(pem, "0.0.0.0", "2222", prefs)
    let auth = TCPListenAuth(env.root)
    SshListener(auth, config, EchoServerNotify(env))

primitive _EchoServerKey
  fun apply(): Array[U8] val =>
    """Ed25519 private key for the echo server. Test-only, not for production."""
    (recover val
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIL5WXOw5lzhPk0Y4iNRzTuq+lGgyONPJrY0XOsqPtuAD\n" +
      "-----END PRIVATE KEY-----\n"
    end).array()

primitive _AuthorizedKey
  fun apply(): Array[U8] val =>
    """
    Authorized public key blob (base64-decoded from ~/.ssh/id_ed25519.pub).
    Replace this with your own key.
    """
    try
      Base64.decode[Array[U8] iso](
        "AAAAC3NzaC1lZDI1NTE5AAAAIFt4LNU1hzaNa3ap5OIrKey19KHD8clnopA5BgODuVtx")?
    else
      recover val Array[U8] end
    end

actor EchoServerNotify is SshServerNotify
  let _env: Env
  let _authorized_key: Array[U8] val = _AuthorizedKey()
  var _last_username: String val = ""
  var _reader: Reader = Reader

  new create(env: Env) => _env = env

  be ssh_session_started(session: SshSession tag) =>
    _env.out.print("New connection")

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    _env.out.print("Auth from: " + request.username + " (" + request.method + ")")
    match request.method_data
    | let pw: SshAuthPasswordData val =>
      if pw.password == "wibble" then
        _last_username = request.username
        session.auth_accept()
      else
        _env.out.print("  wrong password")
        let remaining = recover val
          let a = Array[String val]
          a.push("publickey")
          a.push("password")
          a
        end
        session.auth_reject(remaining)
      end
    | let pk: SshAuthPublicKeyData val =>
      // Check if offered key matches our authorized key (constant-time)
      if not SshMac.verify(pk.public_key, _authorized_key) then
        _env.out.print("  publickey rejected — unknown key")
        let remaining = recover val
          let a = Array[String val]
          a.push("publickey")
          a.push("password")
          a
        end
        session.auth_reject(remaining)
        return
      end
      match pk.signature
      | None =>
        // Query: client asks if this key is acceptable.
        _env.out.print("  publickey query for " + pk.algorithm + " — key recognized")
        session.auth_pk_ok(pk.algorithm, pk.public_key)
      | let _: Array[U8] val =>
        // Actual auth with signature from a recognized key.
        _env.out.print("  publickey auth with " + pk.algorithm + " — accepted")
        _last_username = request.username
        session.auth_accept()
      end
    else
      // Reject other methods, offer publickey and password
      let remaining = recover val
        let a = Array[String val]
        a.push("publickey")
        a.push("password")
        a
      end
      session.auth_reject(remaining)
    end

  be ssh_session_ready(session: SshSession tag) => None

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    _env.out.print("Channel open: " + channel_type)
    session.accept_channel(channel_id)

  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  =>
    _env.out.print("PTY request: " + pty.term
      + " " + pty.width_chars.string() + "x" + pty.height_rows.string())
    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    _env.out.print("Shell request")
    if want_reply then
      session.accept_request(channel_id)
    end
    let msg: String val = "Welcome to ponyssh echo server, " + _last_username + "!\r\n"
    let greeting: Array[U8] val = recover val
      let a = Array[U8](msg.size())
      for ch in msg.values() do a.push(ch) end
      a
    end
    session.channel_send(channel_id, greeting)

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
  =>
    _env.out.print("Window change: " + width_chars.string() + "x" + height_rows.string())

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  =>
    _env.out.print("Channel request: " + request_type)
    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    let input = String.from_array(data)
    _reader.append(input)
    var line: String val = ""
    for chr in data.values() do
      _env.out.print("chr: " + chr.string())
    end
    _env.out.print("R: " + input)
    try
      while (true) do
        line = _reader.line()?
        _env.out.print("line: " + line)
        session.channel_send(channel_id, line.array())
      end
    else
      _env.out.print("Size: " + _reader.size().string())
    end

    if input.contains("/quit") then
      let bye: Array[U8] val = recover val
        let msg = "Goodbye!\r\n"
        let a = Array[U8](msg.size())
        for ch in msg.values() do a.push(ch) end
        a
      end
      session.channel_send(channel_id, bye)
      session.disconnect()
    else
      // Echo back
      session.channel_send(channel_id, data)
    end

  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val)
  =>
    _env.out.print("Channel error: " + err.string())

  be ssh_channel_closed(session: SshSession tag, channel_id: U32) =>
    _env.out.print("Channel closed")

  be ssh_error(session: SshSession tag, err: SshTransportError val) =>
    _env.out.print("Error: " + err.string())

  be ssh_disconnected(session: SshSession tag) =>
    _env.out.print("Client disconnected")
