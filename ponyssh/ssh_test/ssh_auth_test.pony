use "pony_test"
use "../ssh_transport"
use "../ssh_error"
use "../ssh_auth"

class iso _TestAuthMessageEncode is UnitTest
  fun name(): String => "ssh_auth/message/encode_password_request"

  fun apply(h: TestHelper) =>
    let msg = SshAuthMessages.userauth_request_password("alice", "ssh-connection", "s3cr3t")

    // First byte must be SSH_MSG_USERAUTH_REQUEST (50)
    let first = try msg(0)? else h.fail("empty message"); return end
    h.assert_eq[U8](first, SshAuthMsgTypes.userauth_request())

    // Username "alice" must appear as a substring in the encoded bytes
    let as_str = String.from_array(msg)
    h.assert_true(as_str.contains("alice"), "username 'alice' not found in encoded message")
    h.assert_true(as_str.contains("s3cr3t"), "password 's3cr3t' not found in encoded message")
    h.assert_true(as_str.contains("password"), "method 'password' not found in encoded message")

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
