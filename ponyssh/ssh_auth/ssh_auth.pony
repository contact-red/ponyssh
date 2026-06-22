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

  fun val matches(authorized_public_key_blob: Array[U8] val): Bool =>
    """
    True when the presented public key equals the given authorized public key
    blob. The blob is the SSH wire encoding string(algorithm) || string(key) —
    the same bytes found in an OpenSSH .pub file after base64-decoding the
    middle field. Public keys are not secret, so a plain byte comparison is the
    right tool; do not reach for a MAC/constant-time compare to test key
    identity.
    """
    let a = public_key
    let b = authorized_public_key_blob
    if a.size() != b.size() then return false end
    var i: USize = 0
    while i < a.size() do
      if (try a(i)? else return false end) != (try b(i)? else return false end)
      then
        return false
      end
      i = i + 1
    end
    true

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

primitive SshPublicKeyVerifier
  """
  Server-side verification of a client publickey userauth signature per
  RFC 4252 section 7. This proves the client holds the private key for the
  presented public key; the consumer still decides whether that key is
  authorized.
  """
  fun verify(session_id: Array[U8] val, username: String val,
    service: String val, pk: SshAuthPublicKeyData val): Bool
  =>
    """
    Returns true only when pk.signature is a valid signature over the expected
    signed data — string(session_id) || byte(SSH_MSG_USERAUTH_REQUEST) ||
    string(username) || string(service) || string("publickey") || bool(true) ||
    string(algorithm) || string(public_key_blob) — proving possession of the
    private key. Only ssh-ed25519 keys are supported; every other algorithm,
    and any malformed blob, fails closed.
    """
    let signature_blob = match pk.signature
    | let s: Array[U8] val => s
    else
      return false
    end

    try
      // signature blob: string(algorithm) || string(raw_signature)
      let sr = SshWireReader(signature_blob)
      let sig_algo = sr.read_string_as_str()?
      let raw_sig = sr.read_string()?

      // public key blob: string(algorithm) || string(raw_key)
      let kr = SshWireReader(pk.public_key)
      let key_algo = kr.read_string_as_str()?
      let raw_key = kr.read_string()?

      // The advertised, key-blob and signature algorithms must all agree.
      if (pk.algorithm != key_algo) or (sig_algo != key_algo) then
        return false
      end

      // Reconstruct the signed data exactly as the client built it
      // (SshAuthStateMachine.handle_pk_ok).
      let w = SshWireWriter
      w.write_string(session_id)
      w.write_byte(SshAuthMsgTypes.userauth_request())
      w.write_string_from_str(username)
      w.write_string_from_str(service)
      w.write_string_from_str("publickey")
      w.write_bool(true)
      w.write_string_from_str(key_algo)
      w.write_string(pk.public_key)
      let signed = w.val_bytes()

      match SshHostKeyVerify.verify(SshHostKey(key_algo, raw_key), raw_sig,
        signed)
      | true => true
      else false
      end
    else
      false
    end
