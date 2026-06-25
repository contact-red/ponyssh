use "pony_test"
use "../ssh_crypto"
use "../ssh_error"

class iso _TestChacha20Poly1305Roundtrip is UnitTest
  fun name(): String => "ssh_crypto/chacha20poly1305/roundtrip"

  fun apply(h: TestHelper) =>
    // 64-byte key: main_key (0-31) || header_key (32-63)
    let key: Array[U8] val = _TestBytes(64)

    // Build a plaintext SSH packet:
    // packet_length (4 bytes) || padding_length (1 byte) || payload || padding
    let payload: Array[U8] val = "hello chacha20-poly1305".array()
    let padding_length: U8 = 10
    let body_len = 1 + payload.size() + padding_length.usize()
    let plaintext: Array[U8] val = recover val
      let p = Array[U8].create(4 + body_len)
      // packet_length = body_len (big-endian)
      let pl = body_len.u32()
      p.push((pl >> 24).u8())
      p.push((pl >> 16).u8())
      p.push((pl >> 8).u8())
      p.push(pl.u8())
      // padding_length
      p.push(padding_length)
      // payload
      for b in payload.values() do p.push(b) end
      // padding (random-ish, just use zeros for test)
      var i: USize = 0
      while i < padding_length.usize() do p.push(0); i = i + 1 end
      p
    end

    let enc_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create encrypt context"); return
      end
    let enc_result = enc_ctx.encrypt(0, plaintext)
    let ciphertext = match enc_result
    | let c: Array[U8] val =>
      c
    | let err: SshCryptoError =>
      h.fail("encrypt failed: " + err.string()); return
    end

    // Ciphertext should be: 4 (encrypted header) + body_len + 16 (tag)
    h.assert_eq[USize](ciphertext.size(), 4 + body_len + 16)

    let dec_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create decrypt context"); return
      end
    let dec_result = dec_ctx.decrypt(0, ciphertext)
    match dec_result
    | let decrypted: Array[U8] val =>
      h.assert_array_eq[U8](decrypted, plaintext)
    | let err: SshCryptoError =>
      h.fail("decrypt failed: " + err.string())
    end

class iso _TestChacha20Poly1305KnownAnswer is UnitTest
  """
  Pin the exact chacha20-poly1305@openssh.com wire output for a fixed key,
  sequence number, and packet. This is the guard the symmetric round-trip tests
  cannot provide: a refactor that silently reverts to OpenSSL's IETF
  EVP_chacha20_poly1305 AEAD (the original bug) — or mishandles the K_1/K_2
  split, the block counter, or the nonce — still round-trips against itself but
  changes these bytes and breaks OpenSSH interop. The expected value was
  captured from this implementation after verifying a full session against
  OpenSSH 9.6.
  """
  fun name(): String => "ssh_crypto/chacha20poly1305/known_answer"

  fun apply(h: TestHelper) =>
    // Deterministic 64-byte key (bytes 0..63) and a fixed packet:
    // packet_length=13 || padding_length=4 || "ponyssh!" || four 0x00 padding.
    let key = recover val
      let k = Array[U8].create(64)
      var i: USize = 0
      while i < 64 do k.push(i.u8()); i = i + 1 end
      k
    end
    let plaintext = recover val
      let p = Array[U8].create(17)
      p.push(0); p.push(0); p.push(0); p.push(13)  // packet_length = 13
      p.push(4)                                     // padding_length = 4
      for b in "ponyssh!".values() do p.push(b) end // 8-byte payload
      p.push(0); p.push(0); p.push(0); p.push(0)    // 4 padding bytes
      p
    end

    let ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("context create failed"); return
      end
    let out = match ctx.encrypt(7, plaintext)
      | let c: Array[U8] val => c
      | let e: SshCryptoError => h.fail("encrypt failed: " + e.string()); return
      end

    let hexdigits = "0123456789abcdef"
    let actual = recover val
      let s = String(out.size() * 2)
      for b in out.values() do
        try
          s.push(hexdigits(b.usize() >> 4)?)
          s.push(hexdigits((b and 0x0F).usize())?)
        end
      end
      s
    end
    let expected =
      "a39afca72c367a2d37f059364d6dbbf0d762f6b311a46b341a057b67507d35516f"
    h.assert_eq[String](expected, actual)

class iso _TestChacha20Poly1305SequenceNumberMatters is UnitTest
  fun name(): String => "ssh_crypto/chacha20poly1305/sequence_number_matters"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(64)

    let plaintext: Array[U8] val = recover val
      let p = Array[U8].create(20)
      // packet_length = 16 (big-endian)
      p.push(0); p.push(0); p.push(0); p.push(16)
      // padding_length = 10
      p.push(10)
      // payload: 5 bytes
      p.push('h'); p.push('e'); p.push('l'); p.push('l'); p.push('o')
      // padding: 10 bytes
      var i: USize = 0
      while i < 10 do p.push(0); i = i + 1 end
      p
    end

    let enc_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create encrypt context"); return
      end
    let enc_result = enc_ctx.encrypt(0, plaintext)
    let ciphertext = match enc_result
    | let c: Array[U8] val => c
    | let err: SshCryptoError =>
      h.fail("encrypt failed: " + err.string()); return
    end

    // Try decrypting with wrong sequence number
    let dec_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create decrypt context"); return
      end
    let dec_result = dec_ctx.decrypt(1, ciphertext)
    match dec_result
    | let _: Array[U8] val =>
      h.fail("expected decryption with wrong sequence number to fail")
    | let _: SshCryptoError =>
      h.assert_true(true) // expected failure
    end

class iso _TestChacha20Poly1305Corrupted is UnitTest
  fun name(): String => "ssh_crypto/chacha20poly1305/corrupted"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(64)

    let plaintext: Array[U8] val = recover val
      let p = Array[U8].create(20)
      // packet_length = 16 (big-endian)
      p.push(0); p.push(0); p.push(0); p.push(16)
      // padding_length = 10
      p.push(10)
      // payload: 5 bytes
      p.push('h'); p.push('e'); p.push('l'); p.push('l'); p.push('o')
      // padding: 10 bytes
      var i: USize = 0
      while i < 10 do p.push(0); i = i + 1 end
      p
    end

    let enc_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create encrypt context"); return
      end
    let enc_result = enc_ctx.encrypt(0, plaintext)
    let ciphertext = match enc_result
    | let c: Array[U8] val => c
    | let err: SshCryptoError =>
      h.fail("encrypt failed: " + err.string()); return
    end

    // Corrupt a byte in the encrypted body (not header, not tag)
    // Header is bytes 0-3, body starts at 4
    let corrupted: Array[U8] val = recover val
      let arr = Array[U8].create(ciphertext.size())
      for b in ciphertext.values() do arr.push(b) end
      try arr(5)? = arr(5)? xor 0xFF end
      arr
    end

    let dec_ctx =
      try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create decrypt context"); return
      end
    let dec_result = dec_ctx.decrypt(0, corrupted)
    match dec_result
    | let _: Array[U8] val =>
      h.fail("expected decryption of corrupted ciphertext to fail")
    | let _: SshCryptoError =>
      h.assert_true(true) // expected failure
    end
