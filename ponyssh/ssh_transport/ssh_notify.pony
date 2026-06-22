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
  """
  Server-side consumer interface. The session owns the SSH protocol: it sends
  every protocol reply via its own accept_*/reject_* and auth_* behaviors. A
  consumer signals a decision by calling one of those behaviors back on the
  session; it never frames protocol messages itself.

  Authentication and authorization DENY by default. The auth callback's default
  rejects unless validate_password/validate_publickey accept, and every channel
  authorization callback rejects unless overridden — there is no permissive
  default to forget. validate_password and validate_publickey have no default
  at all, so the compiler requires every server to state its auth policy.
  """

  // --- Authentication policy. Consulted by the default ssh_auth_request. ---

  fun validate_password(username: String val, password: String val): Bool
    """Return true to accept this password. No default: state your policy."""

  fun validate_publickey(username: String val,
    pk: SshAuthPublicKeyData val): Bool
    """
    Return true to accept this public key. By the time a signed request reaches
    here the session has already cryptographically verified possession of the
    private key, so this only decides authorization. Use pk.matches(...) to
    compare against an authorized key. No default: state your policy.
    """

  // --- Lifecycle ---

  be ssh_session_started(session: SshSession tag) => None
  be ssh_session_ready(session: SshSession tag) => None

  // --- Authorization. Defaults DENY; override and call session.accept_channel
  // / session.accept_request to grant access. ---

  be ssh_channel_open_request(session: SshSession tag, channel_id: U32,
    channel_type: String val) =>
    // RFC 4254 §5.1 reason 1 = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.
    session.reject_channel(channel_id, 1)

  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool) =>
    if want_reply then session.reject_request(channel_id) end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool) =>
    if want_reply then session.reject_request(channel_id) end

  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool) =>
    if want_reply then session.reject_request(channel_id) end

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32,
    height_pixels: U32) => None

  // --- Data / events. No protocol reply expected. ---

  be ssh_channel_data(session: SshSession tag, channel_id: U32,
    data: Array[U8] val) => None
  be ssh_channel_error(session: SshSession tag, channel_id: U32,
    err: SshChannelError val) => None
  be ssh_channel_closed(session: SshSession tag, channel_id: U32) => None
  be ssh_error(session: SshSession tag, err: SshTransportError val) => None
  be ssh_disconnected(session: SshSession tag) => None

  // --- Authentication dispatch. The session has already verified possession of
  // the private key for a signed publickey request before this is called, so
  // the consumer only ever decides authorization. ---

  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val) =>
    match request.method_data
    | let pw: SshAuthPasswordData val =>
      if validate_password(request.username, pw.password) then
        session.auth_accept()
      else
        session.auth_reject(["publickey"; "password"])
      end
    | let pk: SshAuthPublicKeyData val =>
      if validate_publickey(request.username, pk) then
        match pk.signature
        | None =>
          // Probe: the client is asking whether this key is acceptable. PK_OK
          // tells it to proceed and sign; it grants no access on its own.
          session.auth_pk_ok(pk.algorithm, pk.public_key)
        | let _: Array[U8] val =>
          // Signature already verified by the session; authorization granted.
          session.auth_accept()
        end
      else
        session.auth_reject(["publickey"; "password"])
      end
    else
      session.auth_reject(["publickey"; "password"])
    end
