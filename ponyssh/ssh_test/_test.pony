use "pony_test"
use "pony_check"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_transport"
use "../ssh_auth"
use "../ssh_connection"
use "../ssh_client"

actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  new make() =>
    None

  fun tag tests(test: PonyTest) =>
    test(_TestErrorStrings)
    test(_TestCipherRoundtrip)
    test(_TestCipherDecryptCorrupted)
    test(_TestMacRoundtrip)
    test(_TestMacBitFlip)
    test(_TestKexCurve25519SharedSecret)
    test(_TestKexCurve25519InvalidKey)
    test(_TestHostKeySignVerify)
    test(_TestHostKeySignVerifyCorrupted)
    test(_TestHostKeyPublicKeySize)
    test(_TestPacketRoundtripPlaintext)
    test(_TestPacketPadding)
    test(_TestPacketTooLarge)
    test(_TestPacketSequenceNumbers)
    test(_TestAlgoNegotiateFirstMatch)
    test(_TestAlgoNegotiateNoOverlap)
    test(_TestAlgoNegotiateIdenticalLists)
    test(_TestAlgoNegotiateDefaults)
    test(_TestWireU32Roundtrip)
    test(_TestWireStringRoundtrip)
    test(_TestWireNameListRoundtrip)
    test(_TestKexinitRoundtrip)
    test(_TestKexGenerateKexinit)
    test(_TestKexReceiveAndNegotiate)
    test(_TestKexDeriveKeys)
    test(_TestAuthMessageEncode)
    test(_TestAuthStateMachineTriesMethods)
    test(_TestAuthFailureDecode)
    test(_TestChannelOpenAndConfirm)
    test(_TestChannelDataSendWindowTracking)
    test(_TestChannelClose)
    test(_TestChannelFindByRemoteId)

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
