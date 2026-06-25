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

### Added

- Client channel requests: `SshSession.channel_request_exec` (run a command)
  and `channel_request_shell` (start a login shell), so a client can drive the
  canonical SSH workflow rather than only sending raw channel data.
- `chacha20-poly1305@openssh.com` transport encryption.
- `SshPublicKeyVerifier`, which verifies a client publickey userauth signature
  against an established session id.

### Changed

- Removed `aes128-cbc` from the default cipher preferences.

