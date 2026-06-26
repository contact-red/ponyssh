use "pony_test"
use "../ssh_transport"
use "../ssh_crypto"
use "../ssh_error"
use "../ssh_auth"

class iso _TestStrictKexKexinitMustBeFirst is UnitTest
  """
  Under strict KEX the peer's KEXINIT must be the first binary packet of the
  connection. A packet injected before it makes the reader see the KEXINIT as
  its second packet (sequence 2), which initial_kexinit_position_ok rejects; the
  legitimate case (KEXINIT first → sequence 1) is accepted. This is the
  pre-KEXINIT half of the Terrapin (CVE-2023-48795) mitigation that SshSession
  enforces.
  """
  fun name(): String => "ssh_transport/strict_kex/kexinit_must_be_first"

  fun apply(h: TestHelper) =>
    // The predicate: only a first-packet KEXINIT (reader sequence 1) is ok.
    h.assert_true(SshStrictKex.initial_kexinit_position_ok(1))
    h.assert_false(SshStrictKex.initial_kexinit_position_ok(2))
    h.assert_false(SshStrictKex.initial_kexinit_position_ok(0))

    let prefs = SshDefaultAlgorithms.preferences()
    let cookie: Array[U8] val = recover val Array[U8].init(0, 16) end
    let kexinit =
      SshMessages.kexinit(prefs, cookie, SshStrictKex.client_marker())
    // A packet (SSH_MSG_IGNORE) framed ahead of the KEXINIT.
    let injected: Array[U8] val =
      recover val [as U8: SshMsgTypes.ignore(); 0; 0; 0] end

    // Injected-first: the reader consumes the injected packet (sequence 1) then
    // the KEXINIT (sequence 2), which the position rule rejects.
    let r1 = SshPacketReader
    r1.append(SshPacketWriter.write(injected))
    r1.append(SshPacketWriter.write(kexinit))
    var read1: USize = 0
    while read1 < 2 do
      match r1.read()
      | let _: Array[U8] val => read1 = read1 + 1
      else h.fail("r1 read did not yield a complete packet"); return
      end
    end
    h.assert_eq[U32](2, r1.sequence_number())
    h.assert_false(SshStrictKex.initial_kexinit_position_ok(r1.sequence_number()))

    // KEXINIT-first: sequence 1, accepted.
    let r2 = SshPacketReader
    r2.append(SshPacketWriter.write(kexinit))
    match r2.read()
    | let _: Array[U8] val => None
    else h.fail("r2 read did not yield a complete packet"); return
    end
    h.assert_eq[U32](1, r2.sequence_number())
    h.assert_true(SshStrictKex.initial_kexinit_position_ok(r2.sequence_number()))

class iso _TestAesGcmKnownAnswer is UnitTest
  """
  AES-256-GCM known-answer test (Galois/Counter Mode spec, Test Case 14): a
  32-byte zero key, 12-byte zero IV and 16-byte zero plaintext with no AAD must
  produce the published ciphertext and tag. This pins the cipher against an
  external reference rather than only round-tripping against itself.
  """
  fun name(): String => "ssh_crypto/cipher/aes_256_gcm_known_answer"

  fun apply(h: TestHelper) =>
    let key: Array[U8] val = recover val Array[U8].init(0, 32) end
    let iv: Array[U8] val = recover val Array[U8].init(0, 12) end
    let plaintext: Array[U8] val = recover val Array[U8].init(0, 16) end
    try
      let ctx = SshCipherContext.aes_256_gcm(key, iv, true)?
      match ctx.encrypt(plaintext, true)
      | let ct: Array[U8] val =>
        h.assert_eq[String val]("cea7403d4d606b6e074ec5d3baf39d18", _hex(ct))
        match ctx.tag_value()
        | let gcm_tag: Array[U8] val =>
          h.assert_eq[String val]("d0d1c8a799996bf0265b98b5d48ab919",
            _hex(gcm_tag))
        | None => h.fail("no GCM tag produced")
        end
      | let e: SshCryptoError => h.fail("encrypt failed: " + e.string())
      end
    else
      h.fail("aes_256_gcm context creation failed")
    end

  fun _hex(bytes: Array[U8] val): String val =>
    let digits = "0123456789abcdef"
    let out = recover iso String(bytes.size() * 2) end
    for b in bytes.values() do
      try
        out.push(digits(b.usize() >> 4)?)
        out.push(digits(b.usize() and 0xf)?)
      end
    end
    consume out

class iso _TestPacketReaderRejectsBadPadding is UnitTest
  """
  The plaintext packet reader must reject a packet whose padding_length is below
  the minimum of 4, or whose padding overruns packet_length, rather than
  under-reading or wedging. These reject branches sit on the path that decodes
  every unencrypted packet, and the writer never produces such packets, so only
  a hand-crafted frame exercises them.
  """
  fun name(): String => "ssh_transport/packet/reader_rejects_bad_padding"

  fun apply(h: TestHelper) =>
    // packet_length 8 with padding_length 2 — below the minimum of 4.
    _expect_corrupt(h, _frame(8, 2))
    // padding_length 200 overruns packet_length 8.
    _expect_corrupt(h, _frame(8, 200))

  fun _frame(packet_length: U32, padding_length: U8): Array[U8] val =>
    // packet_length(4 BE) || padding_length(1) || filler to packet_length bytes.
    recover val
      let b = Array[U8]
      b.push((packet_length >> 24).u8()); b.push((packet_length >> 16).u8())
      b.push((packet_length >> 8).u8()); b.push(packet_length.u8())
      b.push(padding_length)
      var i: U32 = 1
      while i < packet_length do b.push(0); i = i + 1 end
      b
    end

  fun _expect_corrupt(h: TestHelper, framed: Array[U8] val) =>
    let r = SshPacketReader
    r.append(framed)
    match r.read()
    | SshPacketCorrupt => None
    | let other: SshTransportError =>
      h.fail("expected SshPacketCorrupt, got " + other.string())
    | let _: Array[U8] val => h.fail("expected SshPacketCorrupt, got payload")
    | None => h.fail("expected SshPacketCorrupt, got None (incomplete)")
    end

class iso _TestPubkeyProbeThenSignVerifies is UnitTest
  """
  Drive the real client auth state machine through the publickey probe → PK_OK →
  sign sequence, then feed the signed request it produces into the real
  server-side verifier. The loop must close — a signature the client actually
  builds in handle_pk_ok verifies against the same session id — and a different
  session id must fail. This exercises the production producer (not a fixture)
  end to end.
  """
  fun name(): String => "ssh_auth/pubkey/probe_then_sign_verifies"

  fun apply(h: TestHelper) =>
    let session_id: Array[U8] val = recover val
      let a = Array[U8](32)
      var i: USize = 0
      while i < 32 do a.push(i.u8()); i = i + 1 end
      a
    end
    let methods: Array[SshAuthMethod val] val =
      recover val
        [as SshAuthMethod val: SshPublicKeyAuth(_TestEd25519Pem())]
      end
    let sm = SshAuthStateMachine("testuser", methods)

    // Probe first (no signature); this also loads the keypair for the sign step.
    match sm.next_request()
    | let _: Array[U8] val => None
    | SshAuthRejected =>
      h.fail("probe request rejected")
      return
    end

    let signed = match sm.handle_pk_ok(session_id)
      | let req: Array[U8] val => req
      | SshAuthRejected =>
        h.fail("handle_pk_ok rejected")
        return
      end

    // Parse the signed USERAUTH_REQUEST exactly as the server does.
    try
      let r = SshWireReader(signed)
      r.read_byte()?  // SSH_MSG_USERAUTH_REQUEST
      let username = r.read_string_as_str()?
      let service = r.read_string_as_str()?
      r.read_string_as_str()?  // method == "publickey"
      let has_sig = r.read_bool()?
      let algo = r.read_string_as_str()?
      let pk_blob = r.read_string()?
      let sig = r.read_string()?
      h.assert_true(has_sig)
      let pkd = SshAuthPublicKeyData(algo, pk_blob, sig)
      h.assert_true(
        SshPublicKeyVerifier.verify(session_id, username, service, pkd),
        "real signed request must verify against the same session id")

      // Negative control: the signature is bound to the session id, so a
      // different id must not verify.
      let other_id: Array[U8] val = recover val Array[U8].init(7, 32) end
      h.assert_false(
        SshPublicKeyVerifier.verify(other_id, username, service, pkd),
        "signature bound to session id must fail under a different id")
    else
      h.fail("could not parse the signed userauth request")
    end
