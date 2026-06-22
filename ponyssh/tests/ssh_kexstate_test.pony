use "pony_test"
use "../ssh_transport"
use "../ssh_error"
use "../ssh_crypto"

class iso _TestKexGenerateKexinit is UnitTest
  fun name(): String => "ssh_transport/kexstate/generate_kexinit"

  fun apply(h: TestHelper) =>
    let prefs = SshDefaultAlgorithms.preferences()
    let kex = SshKexStateMachine(SshRoleClient)
    let payload =
      try kex.generate_kexinit(prefs)?
      else h.fail("generate_kexinit failed"); return
      end

    // Decode and verify fields match original prefs
    let decoded =
      try
        match SshMessages.decode_kexinit(payload)?
        | let p: SshAlgorithmPreferences val => p
        | None => h.fail("decode_kexinit returned None"); return
        end
      else
        h.fail("decode_kexinit raised error"); return
      end

    _assert_name_list_eq(h, decoded.kex, prefs.kex, "kex")
    _assert_name_list_eq(h, decoded.host_key, prefs.host_key, "host_key")
    _assert_name_list_eq(h, decoded.cipher_client_to_server,
      prefs.cipher_client_to_server, "cipher_c2s")
    _assert_name_list_eq(h, decoded.cipher_server_to_client,
      prefs.cipher_server_to_client, "cipher_s2c")
    _assert_name_list_eq(h, decoded.mac_client_to_server,
      prefs.mac_client_to_server, "mac_c2s")
    _assert_name_list_eq(h, decoded.mac_server_to_client,
      prefs.mac_server_to_client, "mac_s2c")

  fun _assert_name_list_eq(h: TestHelper, actual: Array[String val] val,
    expected: Array[String val] val, label: String)
  =>
    h.assert_eq[USize](actual.size(), expected.size(),
      label + " list length mismatch")
    var i: USize = 0
    while i < expected.size() do
      let exp = try expected(i)? else return end
      let act = try actual(i)? else
        h.fail(label + "[" + i.string() + "] missing"); return
      end
      h.assert_eq[String val](act, exp, label + "[" + i.string() + "]")
      i = i + 1
    end

class iso _TestKexReceiveAndNegotiate is UnitTest
  fun name(): String => "ssh_transport/kexstate/receive_and_negotiate"

  fun apply(h: TestHelper) =>
    let prefs = SshDefaultAlgorithms.preferences()

    // Client generates KEXINIT
    let client_kex = SshKexStateMachine(SshRoleClient)
    let client_payload =
      try client_kex.generate_kexinit(prefs)?
      else h.fail("generate_kexinit failed"); return
      end

    // Server receives it and negotiates
    let server_kex = SshKexStateMachine(SshRoleServer)
    match server_kex.receive_kexinit(client_payload, prefs)
    | let neg: SshNegotiatedAlgorithms val =>
      // With identical prefs, first choices should win
      h.assert_eq[String val](neg.kex, "curve25519-sha256")
      h.assert_eq[String val](neg.host_key, "ssh-ed25519")
      h.assert_eq[String val](neg.cipher_c2s, "chacha20-poly1305@openssh.com")
      h.assert_eq[String val](neg.cipher_s2c, "chacha20-poly1305@openssh.com")
      h.assert_eq[String val](neg.mac_c2s, "hmac-sha2-256")
      h.assert_eq[String val](neg.mac_s2c, "hmac-sha2-256")
    | let err: SshTransportError =>
      h.fail("expected negotiation to succeed, got: " + err.string())
    end

class iso _TestKexDeriveKeys is UnitTest
  fun name(): String => "ssh_transport/kexstate/derive_keys"

  fun apply(h: TestHelper) =>
    let shared_secret: Array[U8] val = recover val
      let a = Array[U8]
      var i: U8 = 0
      while i < 32 do a.push(i); i = i + 1 end
      a
    end
    let exchange_hash: Array[U8] val = recover val
      let a = Array[U8]
      var i: U8 = 0
      while i < 32 do a.push(i + 100); i = i + 1 end
      a
    end
    let session_id: Array[U8] val = recover val
      let a = Array[U8]
      var i: U8 = 0
      while i < 32 do a.push(i + 200); i = i + 1 end
      a
    end

    let negotiated = SshNegotiatedAlgorithms(
      "curve25519-sha256", "ssh-ed25519",
      "aes256-ctr", "aes256-ctr",
      "hmac-sha2-256", "hmac-sha2-256")

    let kex = SshKexStateMachine(SshRoleClient)
    let keys =
      try
        kex.derive_keys(shared_secret, exchange_hash, session_id, negotiated)?
      else h.fail("derive_keys failed"); return
      end

    // IVs are one SHA-256 round (32 bytes); encryption and MAC keys are
    // derived to 64 bytes via the RFC 4253 section 7.2 extension so they can
    // key chacha20-poly1305 (64) and HMAC-SHA-512 (64).
    h.assert_eq[USize](keys.iv_c2s.size(), 32, "iv_c2s size")
    h.assert_eq[USize](keys.iv_s2c.size(), 32, "iv_s2c size")
    h.assert_eq[USize](keys.enc_key_c2s.size(), 64, "enc_key_c2s size")
    h.assert_eq[USize](keys.enc_key_s2c.size(), 64, "enc_key_s2c size")
    h.assert_eq[USize](keys.mac_key_c2s.size(), 64, "mac_key_c2s size")
    h.assert_eq[USize](keys.mac_key_s2c.size(), 64, "mac_key_s2c size")

    // Different letters should produce different keys
    h.assert_false(_arrays_eq(keys.iv_c2s, keys.iv_s2c),
      "iv_c2s and iv_s2c should differ")
    h.assert_false(_arrays_eq(keys.enc_key_c2s, keys.enc_key_s2c),
      "enc_key_c2s and enc_key_s2c should differ")
    h.assert_false(_arrays_eq(keys.iv_c2s, keys.enc_key_c2s),
      "iv_c2s and enc_key_c2s should differ")
    h.assert_false(_arrays_eq(keys.enc_key_c2s, keys.mac_key_c2s),
      "enc_key_c2s and mac_key_c2s should differ")

    // Same inputs produce same outputs (deterministic)
    let kex2 = SshKexStateMachine(SshRoleClient)
    let keys2 =
      try
        kex2.derive_keys(shared_secret, exchange_hash, session_id, negotiated)?
      else h.fail("derive_keys failed"); return
      end
    h.assert_true(_arrays_eq(keys.iv_c2s, keys2.iv_c2s),
      "deterministic: iv_c2s")
    h.assert_true(_arrays_eq(keys.enc_key_c2s, keys2.enc_key_c2s),
      "deterministic: enc_key_c2s")
    h.assert_true(_arrays_eq(keys.mac_key_s2c, keys2.mac_key_s2c),
      "deterministic: mac_key_s2c")

  fun _arrays_eq(a: Array[U8] val, b: Array[U8] val): Bool =>
    if a.size() != b.size() then return false end
    var i: USize = 0
    while i < a.size() do
      try
        if a(i)? != b(i)? then return false end
      else
        return false
      end
      i = i + 1
    end
    true
