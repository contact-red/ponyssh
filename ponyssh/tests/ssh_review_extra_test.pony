use "pony_test"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_connection"
use "../ssh_error"

class iso _TestMacKnownAnswer is UnitTest
  """
  HMAC-SHA256 against RFC 4231 test case 1. A known-answer vector catches
  implementation errors the roundtrip/determinism test cannot — e.g. a MAC that
  returns the key, or the wrong digest — because it pins the exact output.
  """
  fun name(): String => "ssh_crypto/mac/sha256_known_answer"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = recover val Array[U8].init(0x0b, 20) end
    let data: Array[U8] val =
      [as U8: 0x48; 0x69; 0x20; 0x54; 0x68; 0x65; 0x72; 0x65]  // "Hi There"
    let expected: Array[U8] val =
      [as U8: 0xb0; 0x34; 0x4c; 0x61; 0xd8; 0xdb; 0x38; 0x53
              0x5c; 0xa8; 0xaf; 0xce; 0xaf; 0x0b; 0xf1; 0x2b
              0x88; 0x1d; 0xc2; 0x00; 0xc9; 0x83; 0x3d; 0xa7
              0x26; 0xe9; 0x37; 0x6c; 0x2e; 0x32; 0xcf; 0xf7]
    h.assert_array_eq[U8](expected, SshMac.compute_sha256(key, data))

class iso _TestMacDifferentDataDiffers is UnitTest
  """Different data under the same key must produce a non-verifying MAC."""
  fun name(): String => "ssh_crypto/mac/sha256_different_data_differs"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = _TestBytes(32)
    let a = SshMac.compute_sha256(key, "message one".array())
    let b = SshMac.compute_sha256(key, "message two".array())
    h.assert_false(SshMac.verify(a, b),
      "MACs of different data must not verify equal")

class iso _TestMpintRoundtrip is UnitTest
  """
  write_mpint/read_mpint must round-trip. The interesting case is a leading
  byte with the high bit set: write_mpint inserts a leading zero (so the value
  is not read as negative) and read_mpint must strip it again. A canonical
  value (no leading zeros) must come back byte-identical.
  """
  fun name(): String => "ssh_transport/wire/mpint_roundtrip"

  fun apply(h: TestHelper) =>
    let cases: Array[Array[U8] val] val =
      [ recover val Array[U8] end                          // zero
        [as U8: 0x01]
        [as U8: 0x7f]
        [as U8: 0x80]                                      // high bit set
        [as U8: 0x80; 0x00; 0x01]                          // high bit set
        [as U8: 0xff; 0xff; 0xff]                          // all high bits
        [as U8: 0x12; 0x34; 0x56; 0x78; 0x9a] ]
    for value in cases.values() do
      let w = SshWireWriter
      w.write_mpint(value)
      let r = SshWireReader(w.val_bytes())
      match try r.read_mpint()? else None end
      | let got: Array[U8] val => h.assert_array_eq[U8](value, got)
      | None => h.fail("read_mpint failed to decode a written mpint")
      end
    end

class iso _TestChannelAcceptAndWindow is UnitTest
  """
  accept_channel creates server-side state; channel_data_received decrements
  the receive window and returns the remainder.
  """
  fun name(): String => "ssh_channel/accept_and_receive_window"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let local = mgr.accept_channel(0, 5, 0x100000, 0x8000, "session")
    h.assert_eq[USize](1, mgr.channel_count())
    match mgr.get(local)
    | let ch: SshChannelState => h.assert_eq[U32](5, ch.remote_id)
    | None => h.fail("accepted channel not found")
    end

    let initial = SshChannelWindow.initial()
    match mgr.channel_data_received(local, 100)
    | let remaining: U32 => h.assert_eq[U32](initial - 100, remaining)
    | let _: SshChannelError => h.fail("receive within window must succeed")
    end

class iso _TestChannelWindowExhausted is UnitTest
  """Receiving more than the advertised window is a flow-control violation."""
  fun name(): String => "ssh_channel/receive_window_exhausted"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let local = mgr.accept_channel(0, 7, 0x100000, 0x8000, "session")
    let over = SshChannelWindow.initial().usize() + 1
    match mgr.channel_data_received(local, over)
    | let _: U32 => h.fail("over-window receive must be rejected")
    | let err: SshChannelError =>
      h.assert_is[SshChannelError](SshWindowExhausted, err)
    end

class iso _TestChannelReplenish is UnitTest
  """
  replenish_local_window tops the window back up once it falls below half,
  returning the increment to advertise; otherwise None.
  """
  fun name(): String => "ssh_channel/replenish_local_window"

  fun apply(h: TestHelper) =>
    let mgr: SshChannelManager ref = SshChannelManager
    let local = mgr.accept_channel(0, 9, 0x100000, 0x8000, "session")
    let initial = SshChannelWindow.initial()

    // Above half: no adjustment due.
    match mgr.channel_data_received(local, (initial / 4).usize())
    | let _: U32 => None
    | let _: SshChannelError => h.fail("receive within window must succeed")
    end
    match mgr.replenish_local_window(local)
    | let _: U32 => h.fail("no adjustment expected above half window")
    | None => None
    end

    // Drop below half: adjustment tops back up to initial.
    match mgr.channel_data_received(local, (initial / 2).usize())
    | let _: U32 => None
    | let _: SshChannelError => h.fail("receive within window must succeed")
    end
    match mgr.replenish_local_window(local)
    | let inc: U32 =>
      match mgr.get(local)
      | let ch: SshChannelState => h.assert_eq[U32](initial, ch.local_window)
      | None => h.fail("channel vanished")
      end
      h.assert_true(inc > 0)
    | None => h.fail("expected a window adjustment below half")
    end
