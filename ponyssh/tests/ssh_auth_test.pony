use "pony_test"
use "../ssh_transport"
use "../ssh_error"
use "../ssh_auth"

class iso _TestAuthMessageEncode is UnitTest
  fun name(): String => "ssh_auth/message/encode_password_request"

  fun apply(h: TestHelper) =>
    let msg = SshAuthMessages.userauth_request_password(
      "alice", "ssh-connection", "s3cr3t")

    // Decode field-by-field (RFC 4252 §8): byte(SSH_MSG_USERAUTH_REQUEST) ||
    // string(user) || string(service) || string("password") || bool(false) ||
    // string(password). A substring check would miss field reordering or a
    // dropped length prefix; decoding pins the exact structure.
    let r = SshWireReader(msg)
    try
      h.assert_eq[U8](SshAuthMsgTypes.userauth_request(), r.read_byte()?)
      h.assert_eq[String val]("alice", r.read_string_as_str()?)
      h.assert_eq[String val]("ssh-connection", r.read_string_as_str()?)
      h.assert_eq[String val]("password", r.read_string_as_str()?)
      h.assert_false(r.read_bool()?, "the change-password flag must be false")
      h.assert_eq[String val]("s3cr3t", r.read_string_as_str()?)
      h.assert_eq[USize](0, r.remaining(), "no trailing bytes expected")
    else
      h.fail("password userauth request did not decode")
    end

class iso _TestAuthStateMachineTriesMethods is UnitTest
  fun name(): String => "ssh_auth/state_machine/tries_methods_in_order"

  fun apply(h: TestHelper) =>
    let methods: Array[SshAuthMethod val] val = recover val
      let a = Array[SshAuthMethod val]
      a.push(SshNoneAuth)
      a.push(SshPasswordAuth("secret"))
      a
    end
    let sm = SshAuthStateMachine("bob", methods)

    // First request should be a "none" auth
    let req1 =
      match sm.next_request()
      | let bytes: Array[U8] val => bytes
      | SshAuthRejected => h.fail("expected bytes for none, got SshAuthRejected"); return
      end
    let first1 = try req1(0)? else h.fail("empty none request"); return end
    h.assert_eq[U8](first1, SshAuthMsgTypes.userauth_request())
    h.assert_true(String.from_array(req1).contains("none"), "first request should use 'none' method")

    // After failure, should try password
    let req2 =
      match sm.handle_failure()
      | let bytes: Array[U8] val => bytes
      | SshAuthRejected => h.fail("expected bytes for password, got SshAuthRejected"); return
      end
    let first2 = try req2(0)? else h.fail("empty password request"); return end
    h.assert_eq[U8](first2, SshAuthMsgTypes.userauth_request())
    h.assert_true(String.from_array(req2).contains("password"), "second request should use 'password' method")

    // After another failure, all methods exhausted — should return SshAuthRejected
    match sm.handle_failure()
    | SshAuthRejected => None  // expected
    | let _: Array[U8] val => h.fail("expected SshAuthRejected after all methods exhausted")
    end

class iso _TestAuthFailureDecode is UnitTest
  fun name(): String => "ssh_auth/message/failure_roundtrip"

  fun apply(h: TestHelper) =>
    let methods: Array[String val] val = recover val
      let a = Array[String val]
      a.push("publickey")
      a.push("password")
      a
    end
    let encoded = SshAuthMessages.userauth_failure(methods, false)
    match SshAuthMessages.decode_userauth_failure(encoded)
    | (let decoded_methods: Array[String val] val, let partial: Bool) =>
      h.assert_eq[USize](decoded_methods.size(), 2, "method count")
      let m0 = try decoded_methods(0)? else h.fail("methods(0) missing"); return end
      let m1 = try decoded_methods(1)? else h.fail("methods(1) missing"); return end
      h.assert_eq[String val](m0, "publickey")
      h.assert_eq[String val](m1, "password")
      h.assert_false(partial, "partial should be false")
    | None =>
      h.fail("decode_userauth_failure returned None")
    end
