use "lori"
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
    // Force AES-256-GCM as the only cipher to ensure our per-packet GCM
    // encryption is used. Other algorithms are not yet fully wired.
    let gcm_only = recover val
      let a = Array[String val]
      a.push("aes256-gcm@openssh.com")
      a
    end
    let prefs = SshAlgorithmPreferences(
      recover val let a = Array[String val]; a.push("curve25519-sha256"); a end,
      recover val let a = Array[String val]; a.push("ssh-ed25519"); a end,
      gcm_only, gcm_only,
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

actor EchoServerNotify is SshServerNotify
  let _env: Env
  var _last_username: String val = ""

  new create(env: Env) => _env = env

  be ssh_session_started(session: SshSession tag) =>
    _env.out.print("New connection")

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    _env.out.print("Auth from: " + request.username)
    _last_username = request.username
    session.auth_accept()

  be ssh_session_ready(session: SshSession tag) => None

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val)
  =>
    _env.out.print("Channel open: " + channel_type)
    session.accept_channel(channel_id)

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  =>
    _env.out.print("Channel request: " + request_type)
    if want_reply then
      session.accept_request(channel_id)
    end
    if request_type == "shell" then
      let msg: String val = "Welcome to ponyssh echo server, " + _last_username + "!\r\n"
      let greeting: Array[U8] val = recover val
        let a = Array[U8](msg.size())
        for ch in msg.values() do a.push(ch) end
        a
      end
      session.channel_send(channel_id, greeting)
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val)
  =>
    let input = String.from_array(data)
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
