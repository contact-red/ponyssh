use "pony_test"
use "../ssh_crypto"
use "../ssh_error"

primitive _TestEd25519Pem
  fun apply(): Array[U8] val =>
    """Test-only Ed25519 private key. Not for production use."""
    (recover val
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIL5WXOw5lzhPk0Y4iNRzTuq+lGgyONPJrY0XOsqPtuAD\n" +
      "-----END PRIVATE KEY-----\n"
    end).array()

class iso _TestHostKeySignVerify is UnitTest
  fun name(): String => "ssh_crypto/hostkey/sign_verify"

  fun apply(h: TestHelper) ? =>
    let pair = SshHostKeyPair.create(_TestEd25519Pem())?
    let pub_key = pair.public_key()

    // Sign and verify several different messages
    let messages: Array[Array[U8] val] val = recover val
      [ recover val [as U8: 1; 2; 3; 4; 5] end
        recover val [as U8: 0; 0; 0; 0; 0; 0; 0; 0] end
        recover val Array[U8].init('A', 256) end
      ]
    end

    for msg in messages.values() do
      match pair.sign(msg)
      | let sig: Array[U8] val =>
        match SshHostKeyVerify.verify(pub_key, sig, msg)
        | true => None
        | let err: SshCryptoError =>
          h.fail("Verification failed: " + err.string())
        end
      | let err: SshCryptoError =>
        h.fail("Signing failed: " + err.string())
      end
    end

class iso _TestHostKeySignVerifyCorrupted is UnitTest
  fun name(): String => "ssh_crypto/hostkey/sign_verify_corrupted"

  fun apply(h: TestHelper) ? =>
    let pair = SshHostKeyPair.create(_TestEd25519Pem())?
    let pub_key = pair.public_key()
    let msg: Array[U8] val = recover val [as U8: 10; 20; 30; 40; 50] end

    match pair.sign(msg)
    | let sig: Array[U8] val =>
      // Corrupt one byte of the signature
      let corrupted = recover iso Array[U8](sig.size()) end
      for byte in sig.values() do
        corrupted.push(byte)
      end
      try corrupted(0)? = corrupted(0)? xor 0xFF end
      let corrupted' = recover val consume corrupted end

      match SshHostKeyVerify.verify(pub_key, corrupted', msg)
      | true =>
        h.fail("Corrupted signature should not verify")
      | let _: SshCryptoError =>
        h.assert_true(true)
      end
    | let err: SshCryptoError =>
      h.fail("Signing failed: " + err.string())
    end

class iso _TestHostKeyPublicKeySize is UnitTest
  fun name(): String => "ssh_crypto/hostkey/public_key_size"

  fun apply(h: TestHelper) ? =>
    let pair = SshHostKeyPair.create(_TestEd25519Pem())?
    let pub_key = pair.public_key()
    h.assert_eq[USize](pub_key.public_key_data.size(), 32)
    h.assert_eq[String](pub_key.algorithm, "ssh-ed25519")
