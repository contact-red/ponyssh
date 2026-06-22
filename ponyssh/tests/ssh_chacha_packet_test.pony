use "pony_test"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_error"

class iso _TestChachaPacketRoundtrip is UnitTest
  """
  A payload framed through SshPacketWriter with chacha20-poly1305 must decrypt
  back to the same bytes through SshPacketReader — and must not appear in
  cleartext on the wire. The cleartext check fails loudly if the writer ever
  regresses to plaintext framing (the chacha-not-wired bug).
  """
  fun name(): String => "ssh_transport/packet/chacha_roundtrip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(64)
    let payload: Array[U8] val = recover val
      [as U8: 0x41; 0x42; 0x43; 0x44; 0x45; 0x46; 0x47; 0x48
              0x49; 0x4a; 0x4b; 0x4c; 0x4d; 0x4e; 0x4f; 0x50]
    end

    let w_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha encrypt context"); return
      end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_chacha20_poly1305(w_ctx)
    let packet: Array[U8] val = writer.write(payload, 8)

    h.assert_false(_contains(packet, payload),
      "payload appeared in cleartext in the chacha packet")

    let r_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha decrypt context"); return
      end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_chacha20_poly1305(r_ctx)
    reader.append(packet)

    match reader.read()
    | let result: Array[U8] val =>
      h.assert_array_eq[U8](payload, result)
    | let err: SshTransportError =>
      h.fail("chacha decrypt failed: " + err.string())
    | None =>
      h.fail("incomplete chacha packet")
    end

  fun _contains(haystack: Array[U8] val, needle: Array[U8] val): Bool =>
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

  fun _matches_at(haystack: Array[U8] val, needle: Array[U8] val, offset: USize):
    Bool
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

class iso _TestChachaPacketCorrupted is UnitTest
  """A single flipped ciphertext byte must be rejected by the poly1305 tag."""
  fun name(): String => "ssh_transport/packet/chacha_corrupted"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(64)
    let payload: Array[U8] val = recover val [as U8: 10; 20; 30; 40; 50] end

    let w_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha encrypt context"); return
      end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_chacha20_poly1305(w_ctx)
    let packet: Array[U8] val = writer.write(payload, 8)

    // Flip a byte inside the encrypted body (after the 4-byte length header).
    let corrupted: Array[U8] val = recover val
      let arr = Array[U8].create(packet.size())
      for b in packet.values() do arr.push(b) end
      try arr(6)? = arr(6)? xor 0xFF end
      arr
    end

    let r_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha decrypt context"); return
      end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_chacha20_poly1305(r_ctx)
    reader.append(corrupted)

    match reader.read()
    | let _: Array[U8] val =>
      h.fail("expected poly1305 to reject the corrupted packet")
    | let _: SshTransportError =>
      h.assert_true(true)
    | None =>
      h.fail("expected error, got None")
    end

class iso _TestChachaPacketSequence is UnitTest
  """
  Two packets written in sequence must each decrypt, proving the per-packet
  sequence-number nonce advances in lockstep on the writer and reader. A
  mismatched nonce would make the second packet's tag fail.
  """
  fun name(): String => "ssh_transport/packet/chacha_sequence"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(64)
    let p1: Array[U8] val = recover val [as U8: 1; 2; 3] end
    let p2: Array[U8] val = recover val [as U8: 9; 8; 7; 6; 5] end

    let w_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha encrypt context"); return
      end
    let writer: SshPacketWriter ref = SshPacketWriter
    writer.set_chacha20_poly1305(w_ctx)
    let pkt1: Array[U8] val = writer.write(p1, 8)
    let pkt2: Array[U8] val = writer.write(p2, 8)

    let r_ctx: SshChacha20Poly1305Context ref = try SshChacha20Poly1305Context(key)?
      else h.fail("failed to create chacha decrypt context"); return
      end
    let reader: SshPacketReader ref = SshPacketReader
    reader.set_chacha20_poly1305(r_ctx)
    reader.append(pkt1)
    reader.append(pkt2)

    match reader.read()
    | let res1: Array[U8] val => h.assert_array_eq[U8](p1, res1)
    else
      h.fail("first chacha packet did not decrypt")
    end

    match reader.read()
    | let res2: Array[U8] val => h.assert_array_eq[U8](p2, res2)
    else
      h.fail("second chacha packet did not decrypt")
    end
