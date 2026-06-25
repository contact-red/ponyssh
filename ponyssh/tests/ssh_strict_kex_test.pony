use "pony_test"
use "../ssh_transport"
use "../ssh_error"

class iso _TestStrictKexPeerAdvertised is UnitTest
  """
  SshStrictKex.peer_advertised detects the peer's role-specific marker in its
  KEXINIT, and only that marker: a client detects the server marker, a server
  detects the client marker, and neither is fooled by the wrong-role marker or
  by a KEXINIT with no marker at all.
  """
  fun name(): String => "ssh_transport/strict_kex/peer_advertised"

  fun apply(h: TestHelper) =>
    let prefs = SshDefaultAlgorithms.preferences()
    let cookie: Array[U8] val = recover val Array[U8].init(0, 16) end

    // A client's first KEXINIT carries the client marker; a server detects it.
    let client_ki =
      SshMessages.kexinit(prefs, cookie, SshStrictKex.client_marker())
    h.assert_true(SshStrictKex.peer_advertised(client_ki, SshRoleServer))

    // A server's first KEXINIT carries the server marker; a client detects it.
    let server_ki =
      SshMessages.kexinit(prefs, cookie, SshStrictKex.server_marker())
    h.assert_true(SshStrictKex.peer_advertised(server_ki, SshRoleClient))

    // No marker → not detected, from either side.
    let plain_ki = SshMessages.kexinit(prefs, cookie)
    h.assert_false(SshStrictKex.peer_advertised(plain_ki, SshRoleServer))
    h.assert_false(SshStrictKex.peer_advertised(plain_ki, SshRoleClient))

    // Wrong-role marker → not detected: a server looks for the *client* marker,
    // so a server marker must not satisfy it (and vice versa).
    h.assert_false(SshStrictKex.peer_advertised(server_ki, SshRoleServer))
    h.assert_false(SshStrictKex.peer_advertised(client_ki, SshRoleClient))

class iso _TestStrictKexMarkerDoesNotWinNegotiation is UnitTest
  """
  The strict-KEX marker is appended last to the kex name-list, so it appears in
  a decoded KEXINIT but never wins negotiation against the real algorithm.
  """
  fun name(): String => "ssh_transport/strict_kex/marker_does_not_win"

  fun apply(h: TestHelper) =>
    let prefs = SshDefaultAlgorithms.preferences()
    let cookie: Array[U8] val = recover val Array[U8].init(0, 16) end
    let marked =
      SshMessages.kexinit(prefs, cookie, SshStrictKex.client_marker())
    try
      match SshMessages.decode_kexinit(marked)?
      | let decoded: SshAlgorithmPreferences val =>
        // The marker is present in the kex list...
        var found = false
        for n in decoded.kex.values() do
          if n == SshStrictKex.client_marker() then found = true end
        end
        h.assert_true(found)
        // ...but negotiation still selects the real key-exchange algorithm.
        match SshAlgorithmNegotiation.negotiate(decoded, prefs)
        | let neg: SshNegotiatedAlgorithms val =>
          h.assert_eq[String val]("curve25519-sha256", neg.kex)
        | SshAlgorithmNegotiationFailed =>
          h.fail("negotiation should still succeed with the marker present")
        end
      | None => h.fail("decode_kexinit returned None for a valid KEXINIT")
      end
    else
      h.fail("decode_kexinit errored on a valid KEXINIT")
    end

class iso _TestPacketResetSequenceNumber is UnitTest
  """
  reset_sequence_number zeroes the per-direction packet counter (used after
  NEWKEYS under strict KEX) and counting resumes from zero afterwards.
  """
  fun name(): String => "ssh_transport/packet/reset_sequence_number"

  fun apply(h: TestHelper) =>
    let payload: Array[U8] val = recover val [as U8: 5; 6; 7] end

    // Writer: two frames advance to 2, reset to 0, next frame is 1.
    let w = SshPacketWriter
    w.write(payload)
    w.write(payload)
    h.assert_eq[U32](2, w.sequence_number())
    w.reset_sequence_number()
    h.assert_eq[U32](0, w.sequence_number())
    w.write(payload)
    h.assert_eq[U32](1, w.sequence_number())

    // Reader: read one plaintext packet to advance to 1, reset to 0.
    let r = SshPacketReader
    let framed: Array[U8] val = SshPacketWriter.write(payload)
    r.append(framed)
    match r.read()
    | let _: Array[U8] val => None
    | let e: SshTransportError => h.fail("read failed: " + e.string())
    | None => h.fail("read returned None for a complete packet")
    end
    h.assert_eq[U32](1, r.sequence_number())
    r.reset_sequence_number()
    h.assert_eq[U32](0, r.sequence_number())
