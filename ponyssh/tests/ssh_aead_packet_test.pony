use "pony_test"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_error"

// Per-packet GCM and stream-cipher (CTR + HMAC) packet framing. These exercise
// the production set_gcm_params / set_stream_cipher paths in SshPacketWriter /
// SshPacketReader — the paths the session actually wires for the aes*-gcm and
// aes*-ctr ciphers. They were previously untested (only the chacha path and the
// legacy single-shot test context had coverage), so a regression in the
// per-packet IV counter, the AAD plumbing, or the two-phase stream read would
// have shipped silently.

primitive _PacketBytes
  fun search(haystack: Array[U8] val, needle: Array[U8] val): Bool =>
    """True if needle appears as a contiguous run within haystack."""
    if needle.size() == 0 then return true end
    if haystack.size() < needle.size() then return false end
    var i: USize = 0
    let last = haystack.size() - needle.size()
    while i <= last do
      if _matches_at(haystack, needle, i) then return true end
      i = i + 1
    end
    false

  fun _matches_at(haystack: Array[U8] val, needle: Array[U8] val,
    offset: USize): Bool
  =>
    var j: USize = 0
    while j < needle.size() do
      try
        if haystack(offset + j)? != needle(j)? then return false end
      else
        return false
      end
      j = j + 1
    end
    true

  fun flip(packet: Array[U8] val, index: USize): Array[U8] val =>
    """Return a copy of packet with one byte at index XOR'd."""
    recover val
      let arr = Array[U8].create(packet.size())
      for b in packet.values() do arr.push(b) end
      try arr(index)? = arr(index)? xor 0xFF end
      arr
    end

class iso _TestGcmPacketRoundtrip is UnitTest
  """
  A payload framed with aes256-gcm@openssh.com via set_gcm_params must decrypt
  back to the same bytes, and must not appear in cleartext on the wire.
  """
  fun name(): String => "ssh_transport/packet/gcm_roundtrip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(12)
    let payload: Array[U8] val = recover val
      [as U8: 0x41; 0x42; 0x43; 0x44; 0x45; 0x46; 0x47; 0x48
              0x49; 0x4a; 0x4b; 0x4c; 0x4d; 0x4e; 0x4f; 0x50]
    end

    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_gcm_params(key, iv)
    let packet: Array[U8] val = writer.write(payload, 16)

    h.assert_false(_PacketBytes.search(packet, payload),
      "payload appeared in cleartext in the gcm packet")

    let reader: SshPacketReader ref = SshPacketReader
    reader.set_gcm_params(key, iv)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val => h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError => h.fail("gcm decrypt failed: " + err.string())
    | None => h.fail("incomplete gcm packet")
    end

class iso _TestGcmPacketCorrupted is UnitTest
  """A single flipped ciphertext byte must be rejected by the GCM tag."""
  fun name(): String => "ssh_transport/packet/gcm_corrupted"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(12)
    let payload: Array[U8] val = recover val [as U8: 10; 20; 30; 40; 50] end

    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_gcm_params(key, iv)
    let packet: Array[U8] val = writer.write(payload, 16)

    // Flip a byte inside the encrypted body (past the 4-byte plaintext length).
    let corrupted = _PacketBytes.flip(packet, 6)

    let reader: SshPacketReader ref = SshPacketReader
    reader.set_gcm_params(key, iv)
    reader.append(corrupted)

    match reader.read()
    | let _: Array[U8] val => h.fail("expected GCM tag to reject corruption")
    | let _: SshTransportError => h.assert_true(true)
    | None => h.fail("expected error, got None")
    end

class iso _TestGcmPacketSequence is UnitTest
  """
  Two GCM packets must each decrypt, proving the per-packet IV counter advances
  in lockstep on writer and reader. A mismatched IV makes the second tag fail.
  """
  fun name(): String => "ssh_transport/packet/gcm_sequence"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(12)
    let p1: Array[U8] val = recover val [as U8: 1; 2; 3] end
    let p2: Array[U8] val = recover val [as U8: 9; 8; 7; 6; 5] end

    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_gcm_params(key, iv)
    let pkt1: Array[U8] val = writer.write(p1, 16)
    let pkt2: Array[U8] val = writer.write(p2, 16)

    let reader: SshPacketReader ref = SshPacketReader
    reader.set_gcm_params(key, iv)
    reader.append(pkt1)
    reader.append(pkt2)

    match reader.read()
    | let res1: Array[U8] val => h.assert_array_eq[U8](p1, res1)
    else h.fail("first gcm packet did not decrypt")
    end
    match reader.read()
    | let res2: Array[U8] val => h.assert_array_eq[U8](p2, res2)
    else h.fail("second gcm packet did not decrypt")
    end

class iso _TestStreamPacketRoundtrip is UnitTest
  """
  A payload framed with aes256-ctr + HMAC-SHA256 via set_stream_cipher must
  decrypt back to the same bytes, and must not appear in cleartext on the wire.
  """
  fun name(): String => "ssh_transport/packet/stream_roundtrip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(16)
    let mac_key: Array[U8] val = _TestBytes(32)
    let payload: Array[U8] val = recover val
      [as U8: 0x61; 0x62; 0x63; 0x64; 0x65; 0x66; 0x67; 0x68; 0x69; 0x6a]
    end

    let w_ctx = try SshCipherContext.aes_256_ctr(key, iv, true)?
      else h.fail("ctr encrypt ctx"); return end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_stream_cipher(w_ctx, mac_key, 32, false)
    let packet: Array[U8] val = writer.write(payload, 16)

    h.assert_false(_PacketBytes.search(packet, payload),
      "payload appeared in cleartext in the stream packet")

    let r_ctx = try SshCipherContext.aes_256_ctr(key, iv, false)?
      else h.fail("ctr decrypt ctx"); return end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_stream_cipher(r_ctx, mac_key, 32, 16, false)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val => h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("stream decrypt failed: " + err.string())
    | None => h.fail("incomplete stream packet")
    end

class iso _TestStreamPacketCorruptedMac is UnitTest
  """A flipped ciphertext byte must fail the trailing HMAC."""
  fun name(): String => "ssh_transport/packet/stream_corrupted_mac"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(16)
    let mac_key: Array[U8] val = _TestBytes(32)
    let payload: Array[U8] val = recover val [as U8: 5; 6; 7; 8; 9; 10] end

    let w_ctx = try SshCipherContext.aes_256_ctr(key, iv, true)?
      else h.fail("ctr encrypt ctx"); return end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_stream_cipher(w_ctx, mac_key, 32, false)
    let packet: Array[U8] val = writer.write(payload, 16)

    // Flip a byte in the first encrypted block (well before the trailing MAC).
    let corrupted = _PacketBytes.flip(packet, 5)

    let r_ctx = try SshCipherContext.aes_256_ctr(key, iv, false)?
      else h.fail("ctr decrypt ctx"); return end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_stream_cipher(r_ctx, mac_key, 32, 16, false)
    reader.append(corrupted)

    match reader.read()
    | let _: Array[U8] val => h.fail("expected HMAC to reject corruption")
    | let _: SshTransportError => h.assert_true(true)
    | None => h.fail("expected error, got None")
    end

class iso _TestStreamPacketSequence is UnitTest
  """
  Two CTR packets must each decrypt, proving the cipher keystream and the
  sequence-number-keyed HMAC advance in lockstep across packets.
  """
  fun name(): String => "ssh_transport/packet/stream_sequence"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(16)
    let mac_key: Array[U8] val = _TestBytes(32)
    let p1: Array[U8] val = recover val [as U8: 1; 2; 3; 4] end
    let p2: Array[U8] val = recover val [as U8: 9; 8; 7] end

    let w_ctx = try SshCipherContext.aes_256_ctr(key, iv, true)?
      else h.fail("ctr encrypt ctx"); return end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_stream_cipher(w_ctx, mac_key, 32, false)
    let pkt1: Array[U8] val = writer.write(p1, 16)
    let pkt2: Array[U8] val = writer.write(p2, 16)

    let r_ctx = try SshCipherContext.aes_256_ctr(key, iv, false)?
      else h.fail("ctr decrypt ctx"); return end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_stream_cipher(r_ctx, mac_key, 32, 16, false)
    reader.append(pkt1)
    reader.append(pkt2)

    match reader.read()
    | let res1: Array[U8] val => h.assert_array_eq[U8](p1, res1)
    else h.fail("first stream packet did not decrypt")
    end
    match reader.read()
    | let res2: Array[U8] val => h.assert_array_eq[U8](p2, res2)
    else h.fail("second stream packet did not decrypt")
    end

class iso _TestStreamPacketSha512 is UnitTest
  """The HMAC-SHA512 (64-byte MAC) branch of the stream path round-trips."""
  fun name(): String => "ssh_transport/packet/stream_sha512_roundtrip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(16)
    let mac_key: Array[U8] val = _TestBytes(64)
    let payload: Array[U8] val = recover val [as U8: 100; 101; 102; 103] end

    let w_ctx = try SshCipherContext.aes_256_ctr(key, iv, true)?
      else h.fail("ctr encrypt ctx"); return end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_stream_cipher(w_ctx, mac_key, 64, true)
    let packet: Array[U8] val = writer.write(payload, 16)

    let r_ctx = try SshCipherContext.aes_256_ctr(key, iv, false)?
      else h.fail("ctr decrypt ctx"); return end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_stream_cipher(r_ctx, mac_key, 64, 16, true)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val => h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("sha512 stream decrypt failed: " + err.string())
    | None => h.fail("incomplete sha512 stream packet")
    end

class iso _TestStreamPacketShortLength is UnitTest
  """
  Regression for the stream reader wedge: a first block whose decrypted
  packet_length is too small to span the block must be rejected, not silently
  buffered forever. We craft a CTR ciphertext whose plaintext length field is 5
  (< the 12-byte minimum for a 16-byte block) and confirm read() errors.
  """
  fun name(): String => "ssh_transport/packet/stream_short_length"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let iv: Array[U8] val = _TestBytes(16)
    let mac_key: Array[U8] val = _TestBytes(32)

    // A 16-byte plaintext first block whose big-endian length field is 5.
    let first_block: Array[U8] val = recover val
      [as U8: 0; 0; 0; 5; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0]
    end
    // Encrypt it with a matching CTR context so the reader decrypts it back.
    let enc = try SshCipherContext.aes_256_ctr(key, iv, true)?
      else h.fail("ctr encrypt ctx"); return end
    let cipher_block = match enc.encrypt_stream(first_block)
      | let c: Array[U8] val => c
      | let _: SshCryptoError => h.fail("ctr encrypt"); return
      end

    let r_ctx = try SshCipherContext.aes_256_ctr(key, iv, false)?
      else h.fail("ctr decrypt ctx"); return end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_stream_cipher(r_ctx, mac_key, 32, 16, false)
    reader.append(cipher_block)

    match reader.read()
    | let _: Array[U8] val => h.fail("expected rejection of short packet_length")
    | let _: SshTransportError => h.assert_true(true)
    | None =>
      h.fail("reader wedged on a too-small packet_length instead of erroring")
    end
