use "pony_test"
use "../ssh_crypto"
use "../ssh_error"

class iso _TestKexCurve25519SharedSecret is UnitTest
  fun name(): String => "ssh_crypto/kex/curve25519_shared_secret"

  fun apply(h: TestHelper) ? =>
    let alice = SshKexCurve25519.create()?
    let bob = SshKexCurve25519.create()?

    let alice_pub = alice.public_key()
    let bob_pub = bob.public_key()

    // Public keys should be 32 bytes for X25519
    h.assert_eq[USize](alice_pub.size(), 32)
    h.assert_eq[USize](bob_pub.size(), 32)

    match alice.derive_shared_secret(bob_pub)
    | let alice_secret: Array[U8] val =>
      match bob.derive_shared_secret(alice_pub)
      | let bob_secret: Array[U8] val =>
        h.assert_eq[USize](alice_secret.size(), 32)
        h.assert_array_eq[U8](alice_secret, bob_secret)
      | let err: SshCryptoError =>
        h.fail("Bob's derivation failed: " + err.string())
      end
    | let err: SshCryptoError =>
      h.fail("Alice's derivation failed: " + err.string())
    end

class iso _TestKexCurve25519InvalidKey is UnitTest
  fun name(): String => "ssh_crypto/kex/curve25519_invalid_key"

  fun apply(h: TestHelper) ? =>
    let alice = SshKexCurve25519.create()?
    // Too-short key
    let bad_key: Array[U8] val = recover val [as U8: 1; 2; 3] end
    match alice.derive_shared_secret(bad_key)
    | let _: Array[U8] val =>
      h.fail("Should have failed with short key")
    | let _: SshCryptoError =>
      h.assert_true(true)
    end
