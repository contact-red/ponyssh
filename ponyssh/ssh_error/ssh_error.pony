primitive SshDecryptFailed is Stringable
  fun string(): String iso^ => "decryption failed".clone()

primitive SshEncryptFailed is Stringable
  fun string(): String iso^ => "encryption failed".clone()

primitive SshMacMismatch is Stringable
  fun string(): String iso^ => "MAC mismatch".clone()

primitive SshSignatureInvalid is Stringable
  fun string(): String iso^ => "signature invalid".clone()

primitive SshKeyInvalid is Stringable
  fun string(): String iso^ => "key invalid".clone()

class val SshOpenSSLError is Stringable
  let code: U64
  let message: String val
  new val create(code': U64, message': String val) =>
    code = code'
    message = message'
  fun string(): String iso^ =>
    ("OpenSSL error " + code.string() + ": " + message).clone()

type SshCryptoError is
  ( SshDecryptFailed
  | SshEncryptFailed
  | SshMacMismatch
  | SshSignatureInvalid
  | SshKeyInvalid
  | SshOpenSSLError )

primitive SshServerHostKeyLoadFailed is Stringable
  """The server host key PEM could not be loaded."""
  fun string(): String iso^ =>
    """The message contains no host key bytes."""
    "server host key could not be loaded".clone()

class val SshServerChannelWindowTooSmall is Stringable
  """The configured channel receive window is below the supported minimum."""
  let given: U32
  let minimum: U32

  new val create(given': U32, minimum': U32) =>
    """The rejected window and minimum remain available for inspection."""
    given = given'
    minimum = minimum'

  fun string(): String iso^ =>
    """The message includes the rejected window and required minimum."""
    ("server channel window " + given.string() +
      " is below minimum " + minimum.string()).clone()

type SshServerConfigError is
  (SshServerHostKeyLoadFailed | SshServerChannelWindowTooSmall)
  """A server host key load failure or an undersized channel window."""

primitive SshPacketTooLarge is Stringable
  fun string(): String iso^ => "packet too large".clone()

primitive SshPacketCorrupt is Stringable
  fun string(): String iso^ => "packet corrupt".clone()

class val SshKexFailed is Stringable
  let inner: SshCryptoError
  new val create(inner': SshCryptoError) => inner = inner'
  fun string(): String iso^ =>
    ("key exchange failed: " + inner.string()).clone()

primitive SshAlgorithmNegotiationFailed is Stringable
  fun string(): String iso^ => "algorithm negotiation failed".clone()

primitive SshProtocolVersionMismatch is Stringable
  fun string(): String iso^ => "protocol version mismatch".clone()

primitive SshConnectionLost is Stringable
  fun string(): String iso^ => "connection lost".clone()

primitive SshRekeyUnsupported is Stringable
  fun string(): String iso^ => "rekeying is not supported".clone()

primitive SshStrictKexViolation is Stringable
  fun string(): String iso^ =>
    "strict key-exchange violation (unexpected packet during handshake)".clone()

primitive SshUnexpectedMessage is Stringable
  fun string(): String iso^ =>
    "unexpected message for the current protocol state".clone()

primitive SshTooManyAuthAttempts is Stringable
  fun string(): String iso^ => "too many authentication attempts".clone()

primitive SshPendingSendsExceeded is Stringable
  fun string(): String iso^ =>
    "deferred send queue exceeded its bound (rekey never completed)".clone()

type SshTransportError is
  ( SshPacketTooLarge
  | SshPacketCorrupt
  | SshKexFailed
  | SshAlgorithmNegotiationFailed
  | SshProtocolVersionMismatch
  | SshConnectionLost
  | SshRekeyUnsupported
  | SshStrictKexViolation
  | SshUnexpectedMessage
  | SshTooManyAuthAttempts
  | SshPendingSendsExceeded )

primitive SshAuthRejected is Stringable
  fun string(): String iso^ => "authentication rejected".clone()

primitive SshAuthProtocolError is Stringable
  fun string(): String iso^ => "authentication protocol error".clone()

class val SshAuthCryptoError is Stringable
  let inner: SshCryptoError
  new val create(inner': SshCryptoError) => inner = inner'
  fun string(): String iso^ =>
    ("authentication crypto error: " + inner.string()).clone()

type SshAuthError is
  ( SshAuthRejected
  | SshAuthProtocolError
  | SshAuthCryptoError )

class val SshChannelOpenFailed is Stringable
  let reason_code: U32
  let description: String val
  new val create(reason_code': U32, description': String val) =>
    reason_code = reason_code'
    description = description'
  fun string(): String iso^ =>
    ("channel open failed (" + reason_code.string() + "): " + description).clone()

class val SshChannelUnsupportedPacketSize is Stringable
  """A peer advertised a channel packet size below the supported minimum."""
  let advertised: U32
  let minimum: U32
  new val create(advertised': U32, minimum': U32) =>
    """Both sizes remain available for caller inspection."""
    advertised = advertised'
    minimum = minimum'
  fun string(): String iso^ =>
    """Include both sizes in the error message."""
    ("peer channel packet size " + advertised.string() +
      " is below minimum " + minimum.string()).clone()

primitive SshChannelClosed is Stringable
  fun string(): String iso^ => "channel closed".clone()

primitive SshWindowExhausted is Stringable
  fun string(): String iso^ => "window exhausted".clone()

type SshChannelError is
  ( SshChannelOpenFailed
  | SshChannelUnsupportedPacketSize
  | SshChannelClosed
  | SshWindowExhausted )
