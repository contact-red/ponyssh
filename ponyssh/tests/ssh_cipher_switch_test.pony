use "pony_test"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_error"

primitive _CipherChacha
primitive _CipherGcm
primitive _CipherStream

type _CipherMode is (_CipherChacha | _CipherGcm | _CipherStream)

primitive _TestPatternBytes
  fun apply(size: USize, seed: U8): Array[U8] val =>
    """
    Deterministic key/IV material. The property under test is which key
    encrypted a given packet, so the two keys involved must be provably
    different rather than different-with-high-probability.
    """
    recover val
      let b = Array[U8].create(size)
      var i: USize = 0
      while i < size do
        b.push(seed + i.u8())
        i = i + 1
      end
      b
    end

primitive _CipherModes
  fun all(): Array[_CipherMode] val =>
    recover val [as _CipherMode: _CipherChacha; _CipherGcm; _CipherStream] end

  fun name(m: _CipherMode): String val =>
    match m
    | _CipherChacha => "chacha20-poly1305"
    | _CipherGcm => "aes256-gcm"
    | _CipherStream => "aes256-ctr"
    end

  fun install_writer(w: SshPacketWriter ref, m: _CipherMode,
    key: Array[U8] val, iv: Array[U8] val): Bool
  =>
    """Install one cipher mode on a writer. False if the context would not build."""
    match m
    | _CipherChacha =>
      try w.set_chacha20_poly1305(SshChacha20Poly1305Context(key)?); true
      else false
      end
    | _CipherGcm =>
      w.set_gcm_params(_first(key, 32), _first(iv, 12))
      true
    | _CipherStream =>
      try
        w.set_stream_cipher(
          SshCipherContext.aes_256_ctr(_first(key, 32), _first(iv, 16), true)?,
          _first(key, 32), 32)
        true
      else false
      end
    end

  fun install_reader(r: SshPacketReader ref, m: _CipherMode,
    key: Array[U8] val, iv: Array[U8] val): Bool
  =>
    """Install one cipher mode on a reader, mirroring install_writer."""
    match m
    | _CipherChacha =>
      try r.set_chacha20_poly1305(SshChacha20Poly1305Context(key)?); true
      else false
      end
    | _CipherGcm =>
      r.set_gcm_params(_first(key, 32), _first(iv, 12))
      true
    | _CipherStream =>
      try
        r.set_stream_cipher(
          SshCipherContext.aes_256_ctr(_first(key, 32), _first(iv, 16), false)?,
          _first(key, 32), 32, 16)
        true
      else false
      end
    end

  fun _first(src: Array[U8] val, n: USize): Array[U8] val =>
    recover val
      let b = Array[U8].create(n)
      var i: USize = 0
      while i < n do
        try b.push(src(i)?) end
        i = i + 1
      end
      b
    end

class iso _TestCipherSwitchUsesNewCipher is UnitTest
  """
  Installing a cipher must displace the one already installed, on both the
  writer and the reader.

  A rekey lets the peer choose a different cipher for the next epoch. When the
  install left the previous cipher's state in place, the packet layer's dispatch
  order decided which one actually ran, and the retired cipher won: traffic kept
  being encrypted under the key that was just rotated away, while strict key
  exchange had already reset the sequence number — which is the ChaCha20 nonce —
  back to zero. That reuses keystream and Poly1305 one-time keys against
  ciphertext an observer recorded earlier in the session.

  Every ordered pair of the three negotiable ciphers is exercised, because the
  defect was per-setter: whichever setter forgot to clear the others was the one
  that leaked. A pair passes only if the newly installed cipher round-trips the
  payload AND the displaced cipher cannot read the same frame.
  """
  fun name(): String => "ssh_transport/packet/cipher_switch_uses_new_cipher"

  fun apply(h: TestHelper) =>
    let key_a: Array[U8] val = _TestPatternBytes(64, 0x01)
    let key_b: Array[U8] val = _TestPatternBytes(64, 0x80)
    let iv_a: Array[U8] val = _TestPatternBytes(16, 0x11)
    let iv_b: Array[U8] val = _TestPatternBytes(16, 0x90)
    let payload: Array[U8] val =
      recover val [as U8: 0x70; 0x6f; 0x6e; 0x79; 0x73; 0x73; 0x68] end

    for first in _CipherModes.all().values() do
      for second in _CipherModes.all().values() do
        if first is second then continue end
        _check_pair(h, first, second, key_a, key_b, iv_a, iv_b, payload)
      end
    end

  fun _check_pair(h: TestHelper, first: _CipherMode, second: _CipherMode,
    key_a: Array[U8] val, key_b: Array[U8] val,
    iv_a: Array[U8] val, iv_b: Array[U8] val, payload: Array[U8] val)
  =>
    let label: String val = _CipherModes.name(first) + " -> " + _CipherModes.name(second)

    // Write one packet under the first cipher, exactly as a session does before
    // a rekey, so the displaced context is one that has already been used.
    let writer: SshPacketWriter ref = SshPacketWriter
    if not _CipherModes.install_writer(writer, first, key_a, iv_a) then
      h.fail("could not install " + _CipherModes.name(first) + " on writer")
      return
    end
    writer.write(payload, 16)

    // Rekey to the second cipher. Strict key exchange resets the sequence
    // number here, which is what turns a stale cipher into nonce reuse.
    if not _CipherModes.install_writer(writer, second, key_b, iv_b) then
      h.fail("could not install " + _CipherModes.name(second) + " on writer")
      return
    end
    writer.reset_sequence_number()
    let packet: Array[U8] val = writer.write(payload, 16)

    // The newly negotiated cipher must be the one that encrypted it.
    let good_reader: SshPacketReader ref = SshPacketReader
    if not _CipherModes.install_reader(good_reader, second, key_b, iv_b) then
      h.fail("could not install " + _CipherModes.name(second) + " on reader")
      return
    end
    good_reader.append(packet)
    match good_reader.read()
    | let result: Array[U8] val =>
      h.assert_array_eq[U8](payload, result,
        "wrong plaintext after switching " + label)
    | let err: SshTransportError =>
      h.fail("packet written after switching " + label
        + " did not decrypt under the new cipher: " + err.string())
    | None =>
      h.fail("packet written after switching " + label + " was incomplete "
        + "under the new cipher, so a different cipher framed it")
    end

    // And the retired cipher must not be able to read it. This is the half that
    // fails when a stale context keeps encrypting under the rotated-away key.
    let stale_reader: SshPacketReader ref = SshPacketReader
    if not _CipherModes.install_reader(stale_reader, first, key_a, iv_a) then
      h.fail("could not install " + _CipherModes.name(first) + " on reader")
      return
    end
    stale_reader.append(packet)
    match stale_reader.read()
    | let result: Array[U8] val =>
      if _equal(payload, result) then
        h.fail("the retired " + _CipherModes.name(first)
          + " cipher still decrypted traffic sent after switching to "
          + _CipherModes.name(second) + ": the key was never rotated")
      end
    end

  fun _equal(a: Array[U8] val, b: Array[U8] val): Bool =>
    if a.size() != b.size() then return false end
    var i: USize = 0
    try
      while i < a.size() do
        if a(i)? != b(i)? then return false end
        i = i + 1
      end
    else
      return false
    end
    true

class iso _TestCipherSwitchDiscardsPartialPacket is UnitTest
  """
  A CTR-mode reader decrypts a packet's first block before the rest of it has
  arrived. That half-read packet belongs to the cipher that decrypted it, so
  installing a new cipher must discard it — otherwise the remainder of the old
  epoch's packet is decrypted under the new key and spliced onto a first block
  from the old one, and the reader stays wedged on a packet that can never
  authenticate.
  """
  fun name(): String => "ssh_transport/packet/cipher_switch_discards_partial_packet"

  fun apply(h: TestHelper) =>
    let key_a: Array[U8] val = _TestPatternBytes(32, 0x01)
    let key_b: Array[U8] val = _TestPatternBytes(32, 0x80)
    let iv_a: Array[U8] val = _TestPatternBytes(16, 0x11)
    let iv_b: Array[U8] val = _TestPatternBytes(16, 0x90)
    let payload: Array[U8] val =
      recover val [as U8: 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15] end

    let writer: SshPacketWriter ref = SshPacketWriter
    let w_ctx: SshCipherContext ref = try SshCipherContext.aes_256_ctr(key_a, iv_a, true)?
      else h.fail("could not build CTR encrypt context"); return
      end
    writer.set_stream_cipher(w_ctx, key_a, 32)
    let old_packet: Array[U8] val = writer.write(payload, 16)

    // Feed only the first block, so the reader decrypts the length header and
    // holds the packet open waiting for the rest.
    let reader: SshPacketReader ref = SshPacketReader
    let r_ctx: SshCipherContext ref = try SshCipherContext.aes_256_ctr(key_a, iv_a, false)?
      else h.fail("could not build CTR decrypt context"); return
      end
    reader.set_stream_cipher(r_ctx, key_a, 32, 16)
    let first_block: Array[U8] val = recover val
      let b = Array[U8].create(16)
      b.copy_from(old_packet, 0, 0, 16)
      b
    end
    reader.append(first_block)
    h.assert_true(reader.read() is None,
      "a lone first block should leave the packet incomplete")

    // Rekey: the new cipher must not inherit the half-read packet.
    let new_ctx: SshCipherContext ref = try SshCipherContext.aes_256_ctr(key_b, iv_b, false)?
      else h.fail("could not build new CTR decrypt context"); return
      end
    reader.set_stream_cipher(new_ctx, key_b, 32, 16)
    reader.reset_sequence_number()

    // A clean packet under the new key must now read, which it cannot do if the
    // old packet's first block is still queued in front of it.
    let new_writer: SshPacketWriter ref = SshPacketWriter
    let nw_ctx: SshCipherContext ref = try SshCipherContext.aes_256_ctr(key_b, iv_b, true)?
      else h.fail("could not build new CTR encrypt context"); return
      end
    new_writer.set_stream_cipher(nw_ctx, key_b, 32)
    reader.append(new_writer.write(payload, 16))

    match reader.read()
    | let result: Array[U8] val =>
      h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("packet under the new key failed: " + err.string()
        + " (the previous cipher's partial packet was carried over)")
    | None =>
      h.fail("packet under the new key never completed: the previous cipher's "
        + "partial packet was carried over")
    end
