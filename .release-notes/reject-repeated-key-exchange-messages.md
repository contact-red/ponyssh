## Reject repeated key-exchange messages

A peer could send SSH_MSG_KEXINIT or SSH_MSG_KEX_ECDH_INIT more than once during a single key exchange.

A repeated SSH_MSG_KEX_ECDH_INIT made a server perform an X25519 key generation, an X25519 derivation, two SHA-256 hashes and an Ed25519 signature for each roughly 48-byte packet received, before the peer had authenticated.

A repeated SSH_MSG_KEXINIT replaced the whole key-exchange state, including a host-key approval a client consumer had not yet answered. The approval a user gave for the key they were shown then applied to a second exchange authenticated by a different key, and the client sent its credentials under that exchange's keys.

Both are now treated as protocol violations and disconnect the session.
