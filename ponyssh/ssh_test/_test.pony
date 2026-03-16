use "pony_test"
use "../ssh_error"

actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  new make() =>
    None

  fun tag tests(test: PonyTest) =>
    test(_TestErrorStrings)

class iso _TestErrorStrings is UnitTest
  fun name(): String => "ssh_error/error_strings"

  fun apply(h: TestHelper) =>
    // Verify all error types produce non-empty strings
    h.assert_true(SshDecryptFailed.string().size() > 0)
    h.assert_true(SshMacMismatch.string().size() > 0)
    h.assert_true(SshSignatureInvalid.string().size() > 0)
    h.assert_true(SshKeyInvalid.string().size() > 0)
    h.assert_true(SshAuthRejected.string().size() > 0)
    h.assert_true(SshChannelClosed.string().size() > 0)
    h.assert_true(SshWindowExhausted.string().size() > 0)

    // Wrapping errors preserve inner context
    let inner: SshCryptoError = SshDecryptFailed
    let kex = SshKexFailed(inner)
    h.assert_true(kex.string().contains("decryption failed"))

    let open_failed = SshChannelOpenFailed(2, "connect failed")
    h.assert_true(open_failed.string().contains("connect failed"))
    h.assert_true(open_failed.string().contains("2"))
