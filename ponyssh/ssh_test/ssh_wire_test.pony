use "pony_test"
use "pony_check"
use "../ssh_transport"
use "../ssh_crypto"

class iso _TestWireU32Roundtrip is UnitTest
  fun name(): String => "ssh_transport/wire/u32_roundtrip"

  fun apply(h: TestHelper) ? =>
    let gen = recover val Generators.u32() end
    PonyCheck.for_all[U32](gen, h)(
      {(value: U32, ph: PropertyHelper) ? =>
        let w = SshWireWriter
        w.write_u32(value)
        let encoded = w.val_bytes()
        let r = SshWireReader(encoded)
        let decoded = r.read_u32()?
        ph.assert_eq[U32](decoded, value)
      })?

class iso _TestWireStringRoundtrip is UnitTest
  fun name(): String => "ssh_transport/wire/string_roundtrip"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(sample: Array[U8] iso, ph: PropertyHelper) ? =>
        let original: Array[U8] val = consume sample
        let w = SshWireWriter
        w.write_string(original)
        let encoded = w.val_bytes()
        let r = SshWireReader(encoded)
        let decoded = r.read_string()?
        ph.assert_array_eq[U8](decoded, original)
      })?

class iso _TestWireNameListRoundtrip is UnitTest
  fun name(): String => "ssh_transport/wire/name_list_roundtrip"

  fun apply(h: TestHelper) =>
    let names: Array[String val] val = recover val
      let a = Array[String val]
      a.push("curve25519-sha256")
      a.push("ecdh-sha2-nistp256")
      a.push("aes256-gcm@openssh.com")
      a
    end

    let w = SshWireWriter
    w.write_name_list(names)
    let encoded = w.val_bytes()

    let r = SshWireReader(encoded)
    let decoded =
      try r.read_name_list()?
      else h.fail("read_name_list raised error"); return
      end

    h.assert_eq[USize](decoded.size(), names.size())
    var i: USize = 0
    while i < names.size() do
      let expected = try names(i)? else ""; h.fail("names index OOB"); return end
      let actual = try decoded(i)? else ""; h.fail("decoded index OOB"); return end
      h.assert_eq[String val](actual, expected)
      i = i + 1
    end

class iso _TestKexinitRoundtrip is UnitTest
  fun name(): String => "ssh_transport/wire/kexinit_roundtrip"

  fun apply(h: TestHelper) =>
    let prefs = SshDefaultAlgorithms.preferences()
    let cookie: Array[U8] val = SshRandom.random_bytes(16)
    let encoded = SshMessages.kexinit(prefs, cookie)

    let decoded =
      try
        match SshMessages.decode_kexinit(encoded)?
        | let p: SshAlgorithmPreferences val => p
        | None => h.fail("decode_kexinit returned None"); return
        end
      else
        h.fail("decode_kexinit raised error"); return
      end

    // Verify all six name-lists match
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
