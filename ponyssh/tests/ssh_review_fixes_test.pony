use "pony_test"
use "../ssh_transport"
use "../ssh_crypto"

class iso _TestWireStringRejectsOversizedLength is UnitTest
  """
  read_string reads an attacker-controlled uint32 length prefix and then asks
  for that many bytes. When the claimed length exceeds the data actually
  present, the decoder must error cleanly rather than over-read or return a
  short buffer. This underlies every wire decoder (name-list, mpint, KEXINIT,
  pubkey verifier), so a missing bound here is a parsing vulnerability.
  """
  fun name(): String => "ssh_transport/wire/string_oversized_length_rejected"

  fun apply(h: TestHelper) =>
    // Each case is a length prefix claiming far more data than follows. A
    // modest-but-oversized length keeps the test deterministic regardless of
    // how the reader allocates; the property under test is "length exceeds
    // available data => error", not the absolute size.
    let cases: Array[Array[U8] val] val =
      [ [as U8: 0x00; 0x00; 0x00; 0x64]                  // claims 100 bytes, 0 follow
        [as U8: 0x00; 0x00; 0xff; 0xff; 0x01; 0x02] ]    // claims 65535, 2 follow
    for bytes in cases.values() do
      let r = SshWireReader(bytes)
      match try r.read_string()? else None end
      | None => None  // errored as required
      | let _: Array[U8] val =>
        h.fail("read_string accepted a length exceeding the available data")
      end
    end

class iso _TestMpintCanonicalStripsLeadingZeros is UnitTest
  """
  An mpint with redundant leading zero bytes must encode identically to its
  canonical form. OpenSSH canonicalizes the X25519 shared secret; a
  non-canonical encoding here diverges the exchange hash on the ~1/256 of
  handshakes where the secret's top byte is zero, breaking interop. Guards the
  fix in SshMpint.canonical / SshWireWriter.write_mpint.
  """
  fun name(): String => "ssh_transport/wire/mpint_canonical_strips_leading_zeros"

  fun apply(h: TestHelper) =>
    // canonical() drops redundant leading zeros.
    h.assert_eq[USize](2,
      SshMpint.canonical([as U8: 0x00; 0x00; 0x12; 0x34]).size())
    // An all-zero magnitude canonicalizes to empty (the encoding of mpint 0).
    h.assert_eq[USize](0, SshMpint.canonical([as U8: 0x00; 0x00]).size())

    // write_mpint of a value with leading zeros equals write_mpint of its
    // canonical value, byte for byte.
    let w_padded = SshWireWriter
    w_padded.write_mpint([as U8: 0x00; 0x00; 0x12; 0x34])
    let w_canon = SshWireWriter
    w_canon.write_mpint([as U8: 0x12; 0x34])
    h.assert_array_eq[U8](w_canon.val_bytes(), w_padded.val_bytes())

    // A value whose canonical high byte has the sign bit set still gets exactly
    // one 0x00 pad: stripping leading zeros then re-adding a single one yields
    // length value-bytes + 1, and read_mpint strips it back to the canonical
    // magnitude.
    let w_high = SshWireWriter
    w_high.write_mpint([as U8: 0x00; 0x80; 0x01])
    // val_bytes() drains the underlying Writer, so capture it once and reuse.
    let high_bytes = w_high.val_bytes()
    let r = SshWireReader(high_bytes)
    h.assert_eq[U32](3, try r.read_u32()? else 0 end)  // 0x00 0x80 0x01
    let back = SshWireReader(high_bytes)
    h.assert_array_eq[U8]([as U8: 0x80; 0x01],
      try back.read_mpint()? else recover val Array[U8] end end)

class iso _TestRandomBytesSucceedsAndDiffers is UnitTest
  """
  SshRandom.random_bytes must succeed and produce different output across
  draws. The crypto round-trip and corruption tests pass even with all-zero
  keys, so they would mask a CSPRNG-returns-failure regression; this test makes
  that regression observable.
  """
  fun name(): String => "ssh_crypto/random/bytes_succeed_and_differ"

  fun apply(h: TestHelper) =>
    try
      let a: Array[U8] val = SshRandom.random_bytes(32)?
      let b: Array[U8] val = SshRandom.random_bytes(32)?
      h.assert_eq[USize](32, a.size())
      h.assert_eq[USize](32, b.size())
      // Two independent 32-byte CSPRNG draws colliding is cryptographically
      // impossible, so equality here means the generator is broken (e.g. a
      // zero-fill fallback).
      h.assert_false(_equal(a, b))
    else
      h.fail("CSPRNG draw failed")
    end

  fun _equal(a: Array[U8] val, b: Array[U8] val): Bool =>
    if a.size() != b.size() then return false end
    var i: USize = 0
    try
      while i < a.size() do
        if a(i)? != b(i)? then return false end
        i = i + 1
      end
    end
    true
