# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a CHANGELOG](http://keepachangelog.com/).

## [unreleased] - unreleased

### Fixed

- Servers no longer act on an inbound `SSH_MSG_USERAUTH_SUCCESS`, closing an
  authentication bypass where a client could reach the connected state without
  presenting any credential.
- Negotiating `chacha20-poly1305@openssh.com` no longer produces an
  unencrypted session. The cipher is now wired into the packet transport, and
  a negotiated cipher the transport cannot apply now tears the connection down
  instead of silently falling back to plaintext.
- Key derivation now performs the RFC 4253 section 7.2 extension, producing
  correct-length key material for ciphers and MACs that need more than 32
  bytes (chacha20-poly1305 and HMAC-SHA-512).
- Servers now verify the client's `publickey` authentication signature
  (RFC 4252 section 7) before accepting it. Previously the signature was never
  checked, so anyone who knew an authorized public key could authenticate.
- Clients no longer begin authentication — sending the username and, for
  password auth, the password — until the consumer has approved the server's
  host key. A rejected host key now tears the connection down before any
  credentials are sent.
- Cryptographic primitives now fail closed instead of returning predictable
  output on OpenSSL failure: `SshRandom.random_bytes` errors rather than
  returning a zero buffer, and `SshHash.sha256` errors rather than returning an
  empty hash (which had become an empty session id and zero-derived keys).
- X25519 key exchange validates the peer public key length and checks the
  `EVP_PKEY_derive` return codes, rejecting malformed or low-order peer keys
  instead of proceeding with a garbage shared secret.
- Cipher encrypt/stream operations check their OpenSSL return codes and fail
  closed; a cipher setup failure on the GCM path no longer emits the plaintext
  packet.
- A mid-session rekey request (`SSH_MSG_KEXINIT` while connected) is now
  rejected with a clean disconnect instead of corrupting the session by
  dropping back into authentication. (Full rekeying remains unimplemented.)
- The pre-handshake version-exchange buffer is now bounded, closing an
  unauthenticated remote memory-exhaustion vector where a peer that never sent
  a line terminator could grow it without limit.
- `SshServerConfig` validates the host key when constructed, so an unparseable
  key fails at setup rather than silently dropping every connection at key
  exchange.
- `chacha20-poly1305@openssh.com` now interoperates with OpenSSH. It was
  implemented on OpenSSL's IETF `EVP_chacha20_poly1305` AEAD, a different
  construction from the OpenSSH variant (separate length key, length keystream
  at block counter 0, payload at counter 1, Poly1305 over the raw
  encrypted length+payload), so it only ever talked to itself. It is now built
  from raw ChaCha20 plus a standalone Poly1305, verified against OpenSSH 9.6.
- Strict key exchange (the OpenSSH `kex-strict-{c,s}-v00@openssh.com`
  extension) is now implemented, mitigating the Terrapin prefix-truncation
  attack (CVE-2023-48795). When the peer also supports it, packet sequence
  numbers reset at every `SSH_MSG_NEWKEYS` and no non-key-exchange packets are
  tolerated during the initial key exchange.
- A peer flooding `SSH_MSG_CHANNEL_OPEN` can no longer grow channel state
  without bound. Servers cap the number of concurrent channels (rejecting
  further opens with `SSH_OPEN_RESOURCE_SHORTAGE`), and clients — which have no
  channel-authorization callback and so would otherwise orphan the state
  forever — reject inbound channel opens without allocating.
- The X25519 shared secret is now encoded as a canonical SSH mpint (leading
  zero bytes stripped). A non-canonical encoding diverged from OpenSSH on the
  ~1/256 of handshakes where the secret's top byte is zero, making the exchange
  hash disagree and the connection fail to establish against OpenSSH.
- A `SSH_MSG_CHANNEL_WINDOW_ADJUST` that would overflow a channel's send-window
  counter now saturates instead of wrapping the window back to a small value.
- More OpenSSL return codes are checked and fail closed: the AEAD decrypt
  update, the HMAC computation, and raw public-key extraction no longer ignore
  a failure from the library.

### Added

- Client channel requests: `SshSession.channel_request_exec` (run a command)
  and `channel_request_shell` (start a login shell), so a client can drive the
  canonical SSH workflow rather than only sending raw channel data.
- `chacha20-poly1305@openssh.com` transport encryption.
- `SshPublicKeyVerifier`, which verifies a client publickey userauth signature
  against an established session id.

### Changed

- Removed `aes128-cbc` support entirely. CBC (encrypt-and-MAC over plaintext)
  is the construction the Terrapin and CBC-padding-oracle attacks target. It
  was already absent from the default preferences but remained negotiable if a
  consumer listed it explicitly; it can no longer be negotiated.

