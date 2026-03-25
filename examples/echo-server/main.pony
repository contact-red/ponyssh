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
  var _terminfo: (TermInfo | None) = None
  var _pty: (SshPtyState val | None) = None

  fun get_vars(): Array[String val] val => _env.vars
  fun get_fileauth(): FileAuth => FileAuth(_env.root)
  fun get_pty(): (SshPtyState val | None) => _pty
  fun ref set_pty(pty: (SshPtyState val | None)) => _pty = pty
  fun get_terminfo(): (TermInfo val | None) => _terminfo
  fun ref set_terminfo(ti: TermInfo val) => _terminfo = ti

  new create(env: Env) =>
    _env = env

  fun validate_password(user: String val, password: String val): Bool => false
  fun validate_publickey(user: String val, pk: SshAuthPublicKeyData val): Bool =>
    SshMac.verify(pk.public_key, _AuthorizedKey())

  fun ref ssh_shell_appstart(session: SshSession tag, channel_id: U32) =>
    let pty: SshPtyState val =
      try
        (get_pty() as SshPtyState)
      else
        session.disconnect("No SshPtyState")
        return
      end

    let terminfo: TermInfo val =
      try
        (get_terminfo() as TermInfo)
      else
        session.disconnect("No supported TermInfo")
        return
      end

    try session.channel_send(channel_id, terminfo.clear_screen()?) end
    for col in Range[I32](0,255) do
      try session.channel_send(channel_id, terminfo.set_foreground(col)?) end
      session.channel_send(channel_id, ("Hello World!" + col.string()).array())
    end

