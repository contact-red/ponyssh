use "pony_test"
use "pony_check"
use "../ssh_crypto"

class iso _TestMacRoundtrip is UnitTest
  fun name(): String => "ssh_crypto/mac/sha256_roundtrip"

  fun apply(h: TestHelper) ? =>
    let data_gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](data_gen, h)(
      {(data: Array[U8] iso, ph: PropertyHelper) =>
        let key: Array[U8] val = _TestBytes(32)
        let d: Array[U8] val = consume data
        let mac1 = SshMac.compute_sha256(key, d)
        let mac2 = SshMac.compute_sha256(key, d)
        ph.assert_true(SshMac.verify(mac1, mac2))
      })?

class iso _TestMacBitFlip is UnitTest
  fun name(): String => "ssh_crypto/mac/sha256_bit_flip"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let data: Array[U8] val = "hello mac bit flip test".array()

    let mac = SshMac.compute_sha256(key, data)

    // Flip one bit in the MAC itself and verify detection
    let flipped: Array[U8] val =
      if mac.size() > 0 then
        let arr = recover iso Array[U8].create(mac.size()) end
        for b in mac.values() do
          arr.push(b)
        end
        try arr(0)? = arr(0)? xor 0x01 end
        consume arr
      else
        mac
      end

    h.assert_false(SshMac.verify(mac, flipped))
