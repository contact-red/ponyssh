use "../ssh_error"
use "../ssh_crypto"
use "../ssh_transport"

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
  var _current_keypair: (SshHostKeyPair | None) = None

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
      SshAuthMessages.userauth_request_password(_username, "ssh-connection",
        pw.password)
    | let pk: SshPublicKeyAuth =>
      // Send publickey query (no signature) to check if server accepts this key
      try
        let keypair = SshHostKeyPair(pk.private_key_data)?
        let pub_key = keypair.public_key()
        let pub_blob = _make_pub_blob(pub_key)
        _current_keypair = keypair
        SshAuthMessages.userauth_request_publickey(
          _username, "ssh-connection", pub_key.algorithm, pub_blob)
      else
        // Key loading failed, skip to next method
        _current_index = _current_index + 1
        next_request()
      end
    | None =>
      SshAuthRejected
    end

  fun ref handle_pk_ok(session_id: Array[U8] val):
    (Array[U8] val | SshAuthRejected)
  =>
    """
    Server accepted our public key query. Now send the actual auth with
    signature per RFC 4252 section 7.
    """
    match _current_keypair
    | let keypair: SshHostKeyPair =>
      let pub_key = keypair.public_key()
      let pub_blob = _make_pub_blob(pub_key)
      // Data to sign: string(session_id) || byte(50) || string(username)
      //   || string(service) || string("publickey") || bool(true)
      //   || string(algorithm) || string(pub_blob)
      let w = SshWireWriter
      w.write_string(session_id)
      w.write_byte(SshAuthMsgTypes.userauth_request())
      w.write_string_from_str(_username)
      w.write_string_from_str("ssh-connection")
      w.write_string_from_str("publickey")
      w.write_bool(true)
      w.write_string_from_str(pub_key.algorithm)
      w.write_string(pub_blob)
      let sign_data = w.val_bytes()

      match keypair.sign(sign_data)
      | let raw_sig: Array[U8] val =>
        // Wrap signature: string(algorithm) || string(raw_sig)
        let sig_w = SshWireWriter
        sig_w.write_string_from_str(pub_key.algorithm)
        sig_w.write_string(raw_sig)
        let sig_blob = sig_w.val_bytes()
        SshAuthMessages.userauth_request_publickey(
          _username, "ssh-connection", pub_key.algorithm, pub_blob, sig_blob)
      | let _: SshCryptoError =>
        SshAuthRejected
      end
    else
      SshAuthRejected
    end

  fun ref handle_failure(): (Array[U8] val | SshAuthRejected) =>
    """Move to next method and generate request, or fail."""
    _current_keypair = None
    _current_index = _current_index + 1
    next_request()

  fun ref handle_success(): None =>
    """Auth succeeded. Nothing to do."""
    None

  fun _make_pub_blob(pub_key: SshHostKey val): Array[U8] val =>
    """Build SSH public key blob: string(algorithm) || string(raw_key_data)."""
    let w = SshWireWriter
    w.write_string_from_str(pub_key.algorithm)
    w.write_string(pub_key.public_key_data)
    w.val_bytes()
