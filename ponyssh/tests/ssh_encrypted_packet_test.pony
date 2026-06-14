use "pony_test"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_error"

class iso _TestEncryptedPacketRoundtrip is UnitTest
  fun name(): String => "ssh_transport/packet/encrypted_roundtrip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = SshRandom.random_bytes(32)
    let iv: Array[U8] val = SshRandom.random_bytes(12)
    let payload: Array[U8] val = recover val [as U8: 1; 2; 3; 4; 5] end

    // Encrypt
    var enc_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, true)?
      else h.fail("failed to create encrypt context"); return
      end
    var writer: SshPacketWriter ref = SshPacketWriter
    writer.set_encrypt_ctx(enc_ctx, true)
    let packet: Array[U8] val = writer.write(payload, 16)

    // Decrypt — need fresh context with same key/iv
    var dec_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, false)?
      else h.fail("failed to create decrypt context"); return
      end
    var reader: SshPacketReader ref = SshPacketReader
    reader.set_decrypt_ctx(dec_ctx, 16, true)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val =>
      h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("decryption failed: " + err.string())
    | None =>
      h.fail("incomplete packet")
    end

class iso _TestEncryptedPacketCorrupted is UnitTest
  fun name(): String => "ssh_transport/packet/encrypted_corrupted"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = SshRandom.random_bytes(32)
    let iv: Array[U8] val = SshRandom.random_bytes(12)
    let payload: Array[U8] val = recover val [as U8: 10; 20; 30; 40; 50] end

    // Encrypt
    var enc_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, true)?
      else h.fail("failed to create encrypt context"); return
      end
    var writer: SshPacketWriter ref = SshPacketWriter
    writer.set_encrypt_ctx(enc_ctx, true)
    let packet: Array[U8] val = writer.write(payload, 16)

    // Corrupt one byte in the encrypted body (byte 5, after the 4-byte header)
    let corrupted: Array[U8] val = recover val
      let arr = Array[U8].create(packet.size())
      for b in packet.values() do arr.push(b) end
      try arr(5)? = arr(5)? xor 0xFF end
      arr
    end

    // Decrypt should fail
    var dec_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, false)?
      else h.fail("failed to create decrypt context"); return
      end
    var reader: SshPacketReader ref = SshPacketReader
    reader.set_decrypt_ctx(dec_ctx, 16, true)
    reader.append(corrupted)

    match reader.read()
    | let _: Array[U8] val =>
      h.fail("expected decryption to fail on corrupted ciphertext")
    | let _: SshTransportError =>
      h.assert_true(true) // expected: corruption detected
    | None =>
      h.fail("expected error, got None")
    end

class iso _TestEncryptedPacketLargePayload is UnitTest
  fun name(): String => "ssh_transport/packet/encrypted_large_payload"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = SshRandom.random_bytes(32)
    let iv: Array[U8] val = SshRandom.random_bytes(12)
    // 1000-byte payload to exercise larger packets
    let payload: Array[U8] val = SshRandom.random_bytes(1000)

    var enc_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, true)?
      else h.fail("failed to create encrypt context"); return
      end
    var writer: SshPacketWriter ref = SshPacketWriter
    writer.set_encrypt_ctx(enc_ctx, true)
    let packet: Array[U8] val = writer.write(payload, 16)

    var dec_ctx: SshCipherContext ref =
      try SshCipherContext.aes_256_gcm(key, iv, false)?
      else h.fail("failed to create decrypt context"); return
      end
    var reader: SshPacketReader ref = SshPacketReader
    reader.set_decrypt_ctx(dec_ctx, 16, true)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val =>
      h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("decryption failed: " + err.string())
    | None =>
      h.fail("incomplete packet")
    end
