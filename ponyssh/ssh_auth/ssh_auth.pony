use "../ssh_error"

class val SshAuthRequest
  """Structured auth request for server consumer."""
  let username: String val
  let method: String val
  let method_data: SshAuthMethodData val

  new val create(username': String val, method': String val,
    method_data': SshAuthMethodData val)
  =>
    username = username'
    method = method'
    method_data = method_data'

type SshAuthMethodData is
  ( SshAuthPasswordData
  | SshAuthPublicKeyData
  | SshAuthNoneData )

class val SshAuthPasswordData
  let password: String val
  new val create(password': String val) => password = password'

class val SshAuthPublicKeyData
  let algorithm: String val
  let public_key: Array[U8] val
  let signature: (Array[U8] val | None)
  new val create(algorithm': String val, public_key': Array[U8] val,
    signature': (Array[U8] val | None) = None)
  =>
    algorithm = algorithm'
    public_key = public_key'
    signature = signature'

primitive SshAuthNoneData

// Config types for client
type SshAuthMethod is (SshPublicKeyAuth | SshPasswordAuth | SshNoneAuth)

class val SshPublicKeyAuth
  let private_key_data: Array[U8] val
  new val create(private_key_data': Array[U8] val) =>
    private_key_data = private_key_data'

class val SshPasswordAuth
  let password: String val
  new val create(password': String val) =>
    password = password'

primitive SshNoneAuth

class SshAuthStateMachine
  """Client-side auth state machine. Tries methods in order."""
  let _methods: Array[SshAuthMethod val] val
  var _current_index: USize = 0
  let _username: String val

  new create(username: String val, methods: Array[SshAuthMethod val] val) =>
    _username = username
    _methods = methods

  fun ref current_method(): (SshAuthMethod val | None) =>
    try _methods(_current_index)? else None end

  fun ref next_request(): (Array[U8] val | SshAuthRejected) =>
    """Generate the next SSH_MSG_USERAUTH_REQUEST payload."""
    match current_method()
    | let _: SshNoneAuth =>
      SshAuthMessages.userauth_request_none(_username, "ssh-connection")
    | let pw: SshPasswordAuth =>
      SshAuthMessages.userauth_request_password(_username, "ssh-connection", pw.password)
    | let _: SshPublicKeyAuth =>
      // For now, just send a none request as placeholder
      // Full implementation requires loading the key and signing
      SshAuthMessages.userauth_request_none(_username, "ssh-connection")
    | None =>
      SshAuthRejected
    end

  fun ref handle_failure(): (Array[U8] val | SshAuthRejected) =>
    """Move to next method and generate request, or fail."""
    _current_index = _current_index + 1
    next_request()

  fun ref handle_success(): None =>
    """Auth succeeded. Nothing to do."""
    None
