## Clamp the channel packet size a peer advertises

The maximum packet size on SSH_MSG_CHANNEL_OPEN and SSH_MSG_CHANNEL_OPEN_CONFIRMATION is a peer-controlled 32-bit value, and it divides outbound channel data. A peer advertising 1 turned every byte of application output into its own SSH packet: 36 bytes on the wire and one AEAD operation per byte. A peer advertising more than the transport's own 35000-byte packet limit produced packets that ponyssh's own reader rejects.

The advertised value is now clamped to between 256 and 32768 bytes when it is stored.
