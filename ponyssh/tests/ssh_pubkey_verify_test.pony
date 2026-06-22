use "pony_test"
use "../ssh_auth"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_error"

primitive _PubkeyVerifyFixture
  """Builders mirroring how a client assembles a publickey userauth request."""
  fun pub_blob(pub: SshHostKey val): Array[U8] val =>
    let w = SshWireWriter
    w.write_string_from_str(pub.algorithm)
    w.write_string(pub.public_key_data)
    w.val_bytes()

  fun signed_data(session_id: Array[U8] val, username: String val,
    service: String val, algorithm: String val, blob: Array[U8] val):
    Array[U8] val
  =>
    let w = SshWireWriter
    w.write_string(session_id)
    w.write_byte(SshAuthMsgTypes.userauth_request())
    w.write_string_from_str(username)
    w.write_string_from_str(service)
    w.write_string_from_str("publickey")
    w.write_bool(true)
    w.write_string_from_str(algorithm)
    w.write_string(blob)
    w.val_bytes()

  fun sig_blob(algorithm: String val, raw_sig: Array[U8] val): Array[U8] val =>
    let w = SshWireWriter
    w.write_string_from_str(algorithm)
    w.write_string(raw_sig)
    w.val_bytes()

class iso _TestPubkeyVerifyValidAccepts is UnitTest
  """
  A signature produced by the matching private key over the correct signed
  data must verify. This is the positive case; if it failed, every rejection
  test below would pass for the wrong reason.
  """
  fun name(): String => "ssh_auth/pubkey_verify/valid_accepts"

  fun apply(h: TestHelper) =>
    let keypair =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load key"); return
      end
    let pub = keypair.public_key()
    let blob = _PubkeyVerifyFixture.pub_blob(pub)
    let sid: Array[U8] val = _TestBytes(32)
    let signed = _PubkeyVerifyFixture.signed_data(sid, "testuser",
      "ssh-connection", pub.algorithm, blob)
    let raw_sig =
      match keypair.sign(signed)
      | let s: Array[U8] val => s
      | let e: SshCryptoError => h.fail("sign failed: " + e.string()); return
      end
    let pk = SshAuthPublicKeyData(pub.algorithm, blob,
      _PubkeyVerifyFixture.sig_blob(pub.algorithm, raw_sig))

    h.assert_true(
      SshPublicKeyVerifier.verify(sid, "testuser", "ssh-connection", pk),
      "a valid signature must verify")

class iso _TestPubkeyVerifyNoSignatureRejected is UnitTest
  """A request carrying no signature (the probe phase) must never verify."""
  fun name(): String => "ssh_auth/pubkey_verify/no_signature_rejected"

  fun apply(h: TestHelper) =>
    let keypair =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load key"); return
      end
    let pub = keypair.public_key()
    let blob = _PubkeyVerifyFixture.pub_blob(pub)
    let pk = SshAuthPublicKeyData(pub.algorithm, blob)  // signature = None

    h.assert_false(
      SshPublicKeyVerifier.verify(_TestBytes(32), "testuser",
        "ssh-connection", pk),
      "a request without a signature must not verify")

class iso _TestPubkeyVerifyGarbageRejected is UnitTest
  """
  Random bytes in place of a real Ed25519 signature must be rejected — an
  attacker who only knows the (public) key cannot fabricate a signature.
  """
  fun name(): String => "ssh_auth/pubkey_verify/garbage_rejected"

  fun apply(h: TestHelper) =>
    let keypair =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load key"); return
      end
    let pub = keypair.public_key()
    let blob = _PubkeyVerifyFixture.pub_blob(pub)
    let pk = SshAuthPublicKeyData(pub.algorithm, blob,
      _PubkeyVerifyFixture.sig_blob(pub.algorithm, _TestBytes(64)))

    h.assert_false(
      SshPublicKeyVerifier.verify(_TestBytes(32), "testuser",
        "ssh-connection", pk),
      "a garbage signature must be rejected")

class iso _TestPubkeyVerifyForgedSignedDataRejected is UnitTest
  """
  A signature valid over one username must not authenticate a request that
  claims a different username — the signed data binds the identity.
  """
  fun name(): String => "ssh_auth/pubkey_verify/forged_signed_data_rejected"

  fun apply(h: TestHelper) =>
    let keypair =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load key"); return
      end
    let pub = keypair.public_key()
    let blob = _PubkeyVerifyFixture.pub_blob(pub)
    let sid: Array[U8] val = _TestBytes(32)
    // Sign the data for "attacker" but present the request as "victim".
    let signed_for_attacker = _PubkeyVerifyFixture.signed_data(sid, "attacker",
      "ssh-connection", pub.algorithm, blob)
    let raw_sig =
      match keypair.sign(signed_for_attacker)
      | let s: Array[U8] val => s
      | let e: SshCryptoError => h.fail("sign failed: " + e.string()); return
      end
    let pk = SshAuthPublicKeyData(pub.algorithm, blob,
      _PubkeyVerifyFixture.sig_blob(pub.algorithm, raw_sig))

    h.assert_false(
      SshPublicKeyVerifier.verify(sid, "victim", "ssh-connection", pk),
      "a signature over different signed data must be rejected")

class iso _TestPubkeyVerifyWrongSessionRejected is UnitTest
  """
  A signature bound to one session id must not verify under another — this
  is what defeats cross-session replay of a captured signature.
  """
  fun name(): String => "ssh_auth/pubkey_verify/wrong_session_rejected"

  fun apply(h: TestHelper) =>
    let keypair =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load key"); return
      end
    let pub = keypair.public_key()
    let blob = _PubkeyVerifyFixture.pub_blob(pub)
    let signed = _PubkeyVerifyFixture.signed_data(_TestBytes(32),
      "testuser", "ssh-connection", pub.algorithm, blob)
    let raw_sig =
      match keypair.sign(signed)
      | let s: Array[U8] val => s
      | let e: SshCryptoError => h.fail("sign failed: " + e.string()); return
      end
    let pk = SshAuthPublicKeyData(pub.algorithm, blob,
      _PubkeyVerifyFixture.sig_blob(pub.algorithm, raw_sig))

    // Verify under a DIFFERENT session id than the one signed over.
    h.assert_false(
      SshPublicKeyVerifier.verify(_TestBytes(32), "testuser",
        "ssh-connection", pk),
      "a signature bound to another session id must be rejected")

class iso _TestPubkeyVerifyWrongKeyRejected is UnitTest
  """
  The core impersonation attack C3 defeats: an attacker presents the
  victim's (public) key but, lacking the victim's private key, signs the
  correct signed data with their OWN key. Verification against the victim's
  key must fail.
  """
  fun name(): String => "ssh_auth/pubkey_verify/wrong_key_rejected"

  fun apply(h: TestHelper) =>
    let victim =
      try SshHostKeyPair(_TestPubkeyPem())?
      else h.fail("could not load victim key"); return
      end
    let attacker =
      try SshHostKeyPair(_TestEd25519Pem())?
      else h.fail("could not load attacker key"); return
      end
    let victim_pub = victim.public_key()
    let victim_blob = _PubkeyVerifyFixture.pub_blob(victim_pub)
    let sid: Array[U8] val = _TestBytes(32)
    // Correct signed data naming the victim's key, signed by the attacker.
    let signed = _PubkeyVerifyFixture.signed_data(sid, "testuser",
      "ssh-connection", victim_pub.algorithm, victim_blob)
    let raw_sig =
      match attacker.sign(signed)
      | let s: Array[U8] val => s
      | let e: SshCryptoError => h.fail("sign failed: " + e.string()); return
      end
    // Present the victim's public key with the attacker's signature.
    let pk = SshAuthPublicKeyData(victim_pub.algorithm, victim_blob,
      _PubkeyVerifyFixture.sig_blob(victim_pub.algorithm, raw_sig))

    h.assert_false(
      SshPublicKeyVerifier.verify(sid, "testuser", "ssh-connection", pk),
      "a signature made by a different key must be rejected (impersonation)")
