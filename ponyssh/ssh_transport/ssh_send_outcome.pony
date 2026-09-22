primitive SshSendComplete
  """Every byte in the submitted array was admitted locally."""

primitive SshSendWindowBlocked
  """The peer's channel window stopped this send."""

primitive SshSendNotReady
  """The channel exists but has not been authorized for data."""

primitive SshSendClosed
  """The channel or session cannot accept more data."""

primitive SshSendTooLarge
  """The submitted array exceeds the per-call limit."""

type SshSendOutcome is
  (SshSendComplete | SshSendWindowBlocked | SshSendNotReady |
    SshSendClosed | SshSendTooLarge)
  """Whether channel_send admitted all data or why it stopped."""
