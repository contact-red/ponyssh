use "../ssh_error"
use "../ssh_crypto"
use "../ssh_connection"
use "../ssh_auth"

interface SshClientNotify
  be ssh_verify_host_key(session: SshSession tag, host: String val, key: SshHostKey val)
  be ssh_ready(session: SshSession tag)
  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val)
  be ssh_channel_opened(session: SshSession tag, channel_id: U32)
  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val)
  be ssh_channel_error(session: SshSession tag, channel_id: U32, err: SshChannelError val)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32)
  be ssh_error(session: SshSession tag, err: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)

interface SshServerNotify
  fun get_pty(): SshPtyState val
  fun ref set_pty(pty: SshPtyState val) => None

  be ssh_session_started(session: SshSession tag) => None
  be ssh_session_ready(session: SshSession tag) => None
  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val) => session.accept_channel(channel_id)

  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool) =>
    set_pty(pty)
//    parse_term_info(pty.term)

    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool) =>
    if want_reply then
      session.accept_request(channel_id)
    end
    ssh_shell_appstart(session, channel_id)

  fun ref ssh_shell_appstart(session: SshSession tag, channel_id: U32) =>
    session.disconnect("You should probably configure an ssh_shell_startup() callback\r\n")

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32) =>
    set_pty(SshPtyState.with_dimensions(get_pty(), width_chars, height_rows, width_pixels, height_pixels))

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool) =>
    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val) =>
    session.disconnect("You should probably configure an ssh_channel_data() callback\r\n")

  be ssh_channel_error(session: SshSession tag, channel_id: U32, err: SshChannelError val) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) => None
  be ssh_disconnected(session: SshSession tag) => None


  fun validate_password(username: String val, password: String val): Bool => false
  fun validate_publickey(username: String val, pk: SshAuthPublicKeyData val): Bool => false

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    match request.method_data
    | let pw: SshAuthPasswordData val =>
      if (validate_password(request.username, pw.password)) then
        session.auth_accept()
      else
        session.auth_reject(["publickey";"password"])
      end
    | let pk: SshAuthPublicKeyData val =>
      if (validate_publickey(request.username, pk)) then
        session.auth_accept()
      else
        session.auth_reject(["publickey";"password"])
      end
    else
      session.auth_reject(["publickey";"password"])
    end

/* FIXME These functions really need to move into primitives in the
   terminfo package and the application being written. 
  fun env_var(key: String): String ? =>
    """Look up an environment variable from Env.vars (Array of KEY=VALUE strings)."""
    let prefix: String val = key + "="
    for entry in get_vars().values() do
      if entry.at(prefix) then
        return entry.substring(prefix.size().isize())
      end
    end
    error

  fun ref parse_term_info(term: String val): (TermInfo val | None) =>
    let dirs = recover val
      let a = Array[String val]
      // Standard terminfo search order
      try a.push(env_var("TERMINFO")?) end
      let home = try env_var("HOME")? else "" end
      if home.size() > 0 then a.push(home + "/.terminfo") end
      try
        let tdirs = env_var("TERMINFO_DIRS")?
        for d in tdirs.split(":").values() do
          if d.size() > 0 then a.push(d) end
        end
      end
      a.push("/usr/share/terminfo")
      a.push("/usr/lib/terminfo")
      a
    end

    let first_char = try
      String.from_array(recover val [term(0)?] end)
    else return
    end

    for dir in dirs.values() do
      let path = FilePath(get_fileauth(), dir + "/" + first_char + "/" + term)
      match OpenFile(path)
      | let file: File =>
        match TIParser.parse(file)
        | let ti: TermInfo =>
          return ti
        | let e: TIParseError => None
        end
      end
    end
*/ 
