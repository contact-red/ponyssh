use "../ssh_transport"
use "../ssh_error"

primitive SshAuthMsgTypes
  fun userauth_request(): U8 => 50
  fun userauth_failure(): U8 => 51
  fun userauth_success(): U8 => 52
  fun userauth_banner(): U8 => 53
  fun service_request(): U8 => 5
  fun service_accept(): U8 => 6

primitive SshAuthMessages
  fun service_request(service_name: String val): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshAuthMsgTypes.service_request())
    w.write_string_from_str(service_name)
    w.val_bytes()

  fun userauth_request_none(username: String val, service: String val): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshAuthMsgTypes.userauth_request())
    w.write_string_from_str(username)
    w.write_string_from_str(service)
    w.write_string_from_str("none")
    w.val_bytes()

  fun userauth_request_password(username: String val, service: String val,
    password: String val): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshAuthMsgTypes.userauth_request())
    w.write_string_from_str(username)
    w.write_string_from_str(service)
    w.write_string_from_str("password")
    w.write_bool(false)
    w.write_string_from_str(password)
    w.val_bytes()

  fun userauth_request_publickey(username: String val, service: String val,
    algorithm: String val, public_key: Array[U8] val,
    signature: (Array[U8] val | None) = None): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshAuthMsgTypes.userauth_request())
    w.write_string_from_str(username)
    w.write_string_from_str(service)
    w.write_string_from_str("publickey")
    match signature
    | let sig: Array[U8] val =>
      w.write_bool(true)
      w.write_string_from_str(algorithm)
      w.write_string(public_key)
      w.write_string(sig)
    | None =>
      w.write_bool(false)
      w.write_string_from_str(algorithm)
      w.write_string(public_key)
    end
    w.val_bytes()

  fun userauth_success(): Array[U8] val =>
    recover val [as U8: SshAuthMsgTypes.userauth_success()] end

  fun userauth_failure(methods: Array[String val] val, partial: Bool): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshAuthMsgTypes.userauth_failure())
    w.write_name_list(methods)
    w.write_bool(partial)
    w.val_bytes()

  fun decode_userauth_failure(data: Array[U8] val): ((Array[String val] val, Bool) | None) =>
    """Decode SSH_MSG_USERAUTH_FAILURE. Returns (methods, partial_success)."""
    try
      let r = SshWireReader(data)
      let msg_type = r.read_byte()?
      if msg_type != SshAuthMsgTypes.userauth_failure() then return None end
      let methods = r.read_name_list()?
      let partial = r.read_bool()?
      (methods, partial)
    else
      None
    end
