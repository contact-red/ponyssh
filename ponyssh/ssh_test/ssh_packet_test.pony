use "pony_test"
use "pony_check"
use "../ssh_transport"
use "../ssh_error"

class iso _TestPacketRoundtripPlaintext is UnitTest
  fun name(): String => "ssh_transport/packet/roundtrip_plaintext"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(sample: Array[U8] iso, ph: PropertyHelper) =>
        let payload: Array[U8] val = consume sample
        let writer = SshPacketWriter
        let packet: Array[U8] val = writer.write(payload)

        let reader = SshPacketReader
        reader.append(packet)
        match reader.read()
        | let result: Array[U8] val =>
          ph.assert_array_eq[U8](result, payload)
        | let err: SshTransportError =>
          ph.fail("reader returned error: " + err.string())
        | None =>
          ph.fail("reader returned None (incomplete packet)")
        end
      })?

class iso _TestPacketPadding is UnitTest
  fun name(): String => "ssh_transport/packet/padding_alignment"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(sample: Array[U8] iso, ph: PropertyHelper) =>
        let payload: Array[U8] val = consume sample
        let writer = SshPacketWriter
        let packet: Array[U8] val = writer.write(payload)

        // Total packet length must be a multiple of 8 (plaintext block size)
        ph.assert_true(
          (packet.size() % 8) == 0,
          "packet size " + packet.size().string() + " is not a multiple of 8")

        // padding_length is at byte 4; must be >= 4
        try
          let padding_length = packet(4)?
          ph.assert_true(
            padding_length.usize() >= 4,
            "padding " + padding_length.string() + " is less than 4")
        else
          ph.fail("could not read padding_length byte")
        end
      })?

class iso _TestPacketTooLarge is UnitTest
  fun name(): String => "ssh_transport/packet/too_large"

  fun apply(h: TestHelper) =>
    // Craft a packet header with packet_length > 35000
    let fake_len: U32 = 40000
    let header = recover val
      let buf = Array[U8].create(4)
      buf.push((fake_len >> 24).u8())
      buf.push((fake_len >> 16).u8())
      buf.push((fake_len >> 8).u8())
      buf.push(fake_len.u8())
      buf
    end

    let reader = SshPacketReader
    reader.append(header)
    match reader.read()
    | SshPacketTooLarge => h.assert_true(true)
    | let _: Array[U8] val =>
      h.fail("expected SshPacketTooLarge, got payload")
    | let err: SshTransportError =>
      h.fail("expected SshPacketTooLarge, got " + err.string())
    | None =>
      h.fail("expected SshPacketTooLarge, got None")
    end

class iso _TestPacketSequenceNumbers is UnitTest
  fun name(): String => "ssh_transport/packet/sequence_numbers"

  fun apply(h: TestHelper) =>
    let writer = SshPacketWriter
    let reader = SshPacketReader

    h.assert_eq[U32](writer.sequence_number(), 0)
    h.assert_eq[U32](reader.sequence_number(), 0)

    var i: U32 = 0
    while i < 3 do
      let payload: Array[U8] val = recover val
        let p = Array[U8].create(10)
        var j: USize = 0
        while j < 10 do
          p.push(i.u8())
          j = j + 1
        end
        p
      end

      let packet: Array[U8] val = writer.write(payload)
      reader.append(packet)
      match reader.read()
      | let result: Array[U8] val =>
        h.assert_array_eq[U8](result, payload)
      | let err: SshTransportError =>
        h.fail("reader error on packet " + i.string() + ": " + err.string())
        return
      | None =>
        h.fail("reader returned None on packet " + i.string())
        return
      end

      h.assert_eq[U32](writer.sequence_number(), i + 1)
      h.assert_eq[U32](reader.sequence_number(), i + 1)

      i = i + 1
    end
