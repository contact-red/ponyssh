use "lori"
use "files"
use "buffered"
use "terminfo"
use "collections"
use "encode/base64"
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
      a.push("chacha20-poly1305@openssh.com")
      a.push("aes256-gcm@openssh.com")
      a.push("aes128-gcm@openssh.com")
      a.push("aes256-ctr")
      a
    end
    let prefs = SshAlgorithmPreferences(
      recover val let a = Array[String val]; a.push("curve25519-sha256"); a end,
      recover val let a = Array[String val]; a.push("ssh-ed25519"); a end,
      ciphers, ciphers,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end,
      recover val let a = Array[String val]; a.push("hmac-sha2-256"); a end)
    let config =
      try SshServerConfig(pem, "0.0.0.0", "2222", prefs)?
      else env.out.print("Invalid host key; aborting."); return
      end
    let auth = TCPListenAuth(env.root)
    SshListener(auth, config, EchoServerNotify(env))

actor EchoServerNotify is SshServerNotify
  let _env: Env
  let _authorized_key: Array[U8] val = _AuthorizedKey()
  // Most recent pty for the shell we will start. A real server would track one
  // per channel; this demo handles a single shell at a time.
  var _pty: SshPtyState val = SshPtyState.none()

  new create(env: Env) =>
    _env = env

  fun validate_password(user: String val, password: String val): Bool =>
    // Don't do this™
    password == "wibble"

  fun validate_publickey(user: String val, pk: SshAuthPublicKeyData val): Bool =>
    pk.matches(_authorized_key)

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    session.accept_channel(channel_id)

  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  =>
    _pty = pty
    if want_reply then session.accept_request(channel_id) end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    if want_reply then session.accept_request(channel_id) end
    let terminfo =
      TermInfos.parse_term_info(_pty.term, FileAuth(_env.root), _env.vars)
    try session.channel_send(channel_id, terminfo.clear_screen()?) end
    for col in Range[I32](0, 255) do
      try session.channel_send(channel_id, terminfo.set_foreground(col)?) end
      session.channel_send(channel_id, ("Hello World!" + col.string()).array())
    end

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

