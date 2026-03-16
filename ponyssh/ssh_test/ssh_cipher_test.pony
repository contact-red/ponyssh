use "pony_test"
use "pony_check"
use "../ssh_crypto"
use "../ssh_error"

class iso _TestCipherRoundtrip is UnitTest
  fun name(): String => "ssh_crypto/cipher/aes_256_gcm_roundtrip"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(plaintext: Array[U8] iso, ph: PropertyHelper) ? =>
        let key: Array[U8] val = SshRandom.random_bytes(32)
        let iv: Array[U8] val = SshRandom.random_bytes(12)
        let pt: Array[U8] val = consume plaintext

        var enc_ctx = SshCipherContext.aes_256_gcm(key, iv, true)?
        let ciphertext = enc_ctx.encrypt(pt, true)
        let gcm_tag = match enc_ctx.tag_value()
        | let t: Array[U8] val => t
        | None => error
        end

        var dec_ctx = SshCipherContext.aes_256_gcm(key, iv, false)?
        dec_ctx.set_tag(gcm_tag)?
        let result = dec_ctx.decrypt(ciphertext)
        match result
        | let decrypted: Array[U8] val =>
          ph.assert_array_eq[U8](decrypted, pt)
        | let err: SshCryptoError =>
          ph.fail("decrypt returned error: " + err.string())
        end
      })?

class iso _TestCipherDecryptCorrupted is UnitTest
  fun name(): String => "ssh_crypto/cipher/aes_256_gcm_corrupted"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = SshRandom.random_bytes(32)
    let iv: Array[U8] val = SshRandom.random_bytes(12)
    let plaintext: Array[U8] val = "hello ssh cipher test".array()

    let enc_ctx =
      try SshCipherContext.aes_256_gcm(key, iv, true)?
      else h.fail("failed to create encrypt context"); return
      end
    var mutable_enc = enc_ctx
    let ciphertext = mutable_enc.encrypt(plaintext, true)
    let gcm_tag = match mutable_enc.tag_value()
    | let t: Array[U8] val => t
    | None => h.fail("no tag after encrypt"); return
    end

    // Corrupt the ciphertext
    let corrupted: Array[U8] val =
      if ciphertext.size() > 0 then
        let arr = recover iso Array[U8].create(ciphertext.size()) end
        for b in ciphertext.values() do
          arr.push(b)
        end
        try arr(0)? = arr(0)? xor 0xFF end
        consume arr
      else
        ciphertext
      end

    let dec_ctx =
      try SshCipherContext.aes_256_gcm(key, iv, false)?
      else h.fail("failed to create decrypt context"); return
      end
    var mutable_dec = dec_ctx
    (try mutable_dec.set_tag(gcm_tag)? else h.fail("set_tag failed"); return end)
    let result = mutable_dec.decrypt(corrupted)
    match result
    | let _: Array[U8] val =>
      h.fail("expected decryption to fail on corrupted ciphertext")
    | let _: SshCryptoError =>
      h.assert_true(true) // expected failure
    end
