# ponyssh — Production-Grade SSH-2 Library for Pony

## Overview

ponyssh is a production-grade SSH-2 client and server library for the Pony
programming language. It implements the core SSH-2 protocol layers — transport,
authentication, and connection/channels — providing a foundation that
higher-level subsystems (SFTP, shell, port forwarding) can build on later.

## Scope

### In scope (v1)

- SSH-2 transport layer (RFC 4253): version exchange, key exchange, packet
  framing, encryption, rekeying
- SSH-2 authentication layer (RFC 4252): none, publickey, password methods
- SSH-2 connection layer (RFC 4254): channel multiplexing, flow control
- Client and server roles
- Modern + widely-deployed cryptographic algorithms via OpenSSL FFI

### Out of scope (v1)

- SSH-1
- Subsystems: SFTP, SCP, interactive shell/PTY, port forwarding
- Agent forwarding
- Certificate-based authentication
- Pure Pony crypto implementations

## Architecture

### Hybrid Session Actor + Crypto Worker Pattern

Each SSH connection is managed by a single `SshSession` actor that owns the TCP
connection and drives the protocol state machine. CPU-intensive cryptographic
operations are offloaded to short-lived worker actors that return results via
`iso` messaging.

**Why this pattern:**

- Single session actor keeps state coordination simple — all protocol
  transitions happen in one actor's sequential execution.
- Crypto workers prevent expensive operations (key exchange, host key
  verification) from blocking the session's message processing.
- Workers communicate via `iso` — no shared mutable state, natural fit for
  Pony's capability system.
- Scales across cores — key exchange computations run on different scheduler
  threads.

**Worker lifecycle:** Workers are short-lived actors created per operation. If
the session tears down while a worker is in flight, the worker's result is
simply never consumed and actor GC handles cleanup.

### State Machine

The session progresses through explicit states:

```
Handshake → KeyExchange → Auth → Connected → Disconnected
```

Represented as a union type:

```pony
type SshSessionState is
  ( SshStateHandshake
  | SshStateKeyExchange
  | SshStateAuth
  | SshStateConnected
  | SshStateDisconnected )
```

Each state is a class holding state-specific data. Transitions are explicit —
the session replaces its `_state` field, consuming the old state.

**Rekeying** is handled as a `Rekeying` sub-state within `SshStateConnected`.

### Session Context

A persistent `SshSessionContext` accumulates connection-lifetime facts alongside
the transient state machine:

```pony
class SshSessionContext
  let remote_addr: NetAddress val
  var negotiated_algorithms: (SshAlgorithms val | None) = None
  var authenticated_as: (SshIdentity val | None) = None
  var session_id: (Array[U8] val | None) = None
  var server_host_key: (SshHostKey val | None) = None
```

This allows consumers to query accumulated information (remote IP, username,
authenticating key, negotiated algorithms) regardless of current state.

### What runs where

**In the session actor (cheap, sequential):**

- State machine transitions
- Packet framing (array manipulation)
- Algorithm negotiation (string matching)
- Channel multiplexing (bookkeeping)

**In crypto workers (expensive, parallelizable):**

- Key exchange computation (DH/ECDH/Curve25519)
- Host key signature generation/verification

**Inline in the session actor (low-latency path):**

- Per-packet encryption/decryption and MAC — these operations are fast for
  typical packet sizes and the actor message-passing overhead of offloading
  them would exceed the crypto cost. Keeping them inline avoids a round-trip
  to a worker for every packet, which matters for interactive sessions.

## Package Structure

All source packages live under `ponyssh/ponyssh/`:

```
ponyssh/
├── ponyssh/
│   ├── ssh_crypto/          # OpenSSL FFI bindings + Pony wrappers
│   │   ├── _ffi.pony        # Raw C FFI declarations (package-private)
│   │   ├── ssh_cipher.pony  # Symmetric ciphers
│   │   ├── ssh_mac.pony     # HMAC (for non-AEAD ciphers)
│   │   ├── ssh_kex.pony     # Key exchange algorithms
│   │   ├── ssh_hostkey.pony # Host key algorithms
│   │   └── ssh_random.pony  # Secure random bytes
│   ├── ssh_transport/       # SSH transport layer (RFC 4253)
│   │   ├── ssh_session.pony # Main Session actor
│   │   ├── ssh_packet.pony  # Packet framing (read/write)
│   │   ├── ssh_kexstate.pony# Key exchange state machine
│   │   └── ssh_algorithms.pony # Algorithm negotiation
│   ├── ssh_auth/            # Authentication layer (RFC 4252)
│   │   ├── ssh_auth.pony    # Auth state machine
│   │   ├── ssh_password.pony
│   │   ├── ssh_publickey.pony
│   │   └── ssh_none.pony
│   ├── ssh_connection/      # Connection layer (RFC 4254)
│   │   ├── ssh_channel.pony # Channel state + multiplexing logic
│   │   └── ssh_manager.pony # Channel lifecycle management
│   ├── ssh_server/          # Server-facing API
│   │   └── ssh_listener.pony
│   ├── ssh_client/          # Client-facing API
│   │   └── ssh_connector.pony
│   ├── _mort.pony           # Panic primitives (Unreachable, IllegalState)
│   └── ssh_test/            # Tests
├── docs/
├── corral.json
└── Makefile
```

**Key design decisions:**

- `ssh_crypto/` is self-contained — no SSH knowledge, only cryptographic
  primitives. Could be extracted as a standalone library.
- `ssh_transport/` contains the session actor and core protocol logic.
  Auth and connection logic are internal modules (classes/primitives)
  called by the session, not separate actors.
- `ssh_server/` and `ssh_client/` are thin public API packages.
- `_mort.pony` at the top level for panic primitives shared across packages:
  - `Unreachable` — code paths the compiler can't prove dead but are logically
    impossible (e.g., `else` after exhaustive size validation)
  - `IllegalState` — state machine violations, functions called in wrong state

## Public API

### Consumer Interaction Model

Consumers interact via actor messaging with notify interfaces. The library
defines interface traits that specify the behaviors the consumer's actor must
implement. Because these interfaces use `be` (behaviors), conforming types must
be actors.

### Client API

```pony
interface SshClientNotify
  be ssh_ready(session: SshSession tag)
  be ssh_auth_failed(session: SshSession tag, error: SshAuthError val)
  be ssh_channel_opened(channel: SshChannel tag)
  be ssh_data(channel: SshChannel tag, data: Array[U8] val)
  be ssh_error(session: SshSession tag, error: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)
```

**Lifecycle:** `ssh_ready` fires after authentication succeeds and the session
enters `SshStateConnected`. The consumer can then open channels. `ssh_error`
delivers transport-level errors. `ssh_disconnected` fires when the connection
ends (after error or clean shutdown).

Usage:

```pony
actor MyApp is SshClientNotify
  new create(env: Env) =>
    let config = SshClientConfig(where
      host' = "example.com",
      port' = "22",
      auth' = SshPublicKeyAuth("/path/to/key"))
    SshConnector(env.root, config, this)

  be ssh_ready(session: SshSession tag) =>
    session.open_channel(this)
  be ssh_disconnected(session: SshSession tag) => ...
  // ... etc
```

### Server API

```pony
interface SshServerNotify
  be ssh_session_started(session: SshSession tag)
  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val)
  be ssh_channel_opened(session: SshSession tag, channel: SshChannel tag)
  be ssh_data(session: SshSession tag, channel: SshChannel tag, data: Array[U8] val)
  be ssh_error(session: SshSession tag, error: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)
```

Auth policy is the consumer's responsibility — the consumer inspects
`SshAuthRequest` and calls `session.auth_accept()` or
`session.auth_reject(remaining_methods)`.

**Sending data:** The server sends data through the `SshChannel` actor received
in `ssh_channel_opened`. The same `channel.send(data)` API is used by both
client and server consumers.

### Channel API

`SshChannel` is a class (not an actor) owned by the session. Consumers receive
a `tag` reference to the session and a channel ID. To send data, consumers call
a behavior on the session:

```pony
session.channel_send(channel_id, data)  // send data
session.channel_close(channel_id)       // close channel
```

The session handles framing, encryption, and flow control internally. This
avoids an extra actor hop per data send (consumer → session → TCP, not
consumer → channel actor → session → TCP).

Internally, `SshChannelManager` tracks per-channel state (window sizes, IDs)
as a class within the session actor.

## Crypto Package

### Design

`ssh_crypto/` wraps OpenSSL via FFI and exposes Pony-idiomatic types. All FFI
declarations are in `_ffi.pony` (package-private). Nothing outside `ssh_crypto`
touches FFI directly.

### Cipher Abstraction

```pony
interface val SshCipherAlgorithm
  fun name(): String
  fun key_len(): USize
  fun iv_len(): USize
  fun block_size(): USize
  fun is_aead(): Bool

class SshCipherContext
  // Wraps EVP_CIPHER_CTX
  fun ref encrypt(plaintext: Array[U8] val): Array[U8] iso^
  fun ref decrypt(ciphertext: Array[U8] val): Array[U8] iso^ ?
```

### Supported Algorithms

| Category | Algorithms |
|----------|-----------|
| Key exchange | curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256, diffie-hellman-group16-sha512 |
| Host key | ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-256, rsa-sha2-512 |
| Cipher | chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr, aes128-cbc (compatibility only, deprioritized — CVE-2008-5161) |
| MAC (non-AEAD) | hmac-sha2-256, hmac-sha2-512 |

### Resource Cleanup

Cipher contexts and key objects wrap OpenSSL pointers. They use `_final()` to
call the corresponding `EVP_*_free` functions, ensuring cleanup when the Pony GC
collects them.

## Transport Layer

### Packet Framing

Per RFC 4253 section 6:

```
uint32    packet_length
byte      padding_length
byte[n1]  payload
byte[n2]  random padding
byte[m]   mac (if active)
```

Two classes owned by the session actor:

- `SshPacketReader` — extracts payload from raw TCP bytes. Delegates
  decryption to cipher context when encryption is active.
- `SshPacketWriter` — frames payload with padding, encrypts if active,
  appends MAC. Returns `Array[U8] iso^`.

Both classes track a `U32` sequence number per direction (send/receive),
incremented per packet. Sequence numbers are used for MAC computation and
must trigger mandatory rekeying before wrapping at 2^32 (per RFC 4253
section 6.4).

**chacha20-poly1305 special handling:** This cipher uses a non-standard packet
format — the packet length field is encrypted separately with a dedicated key
derived from the sequence number. `SshPacketReader`/`SshPacketWriter` must
detect when chacha20-poly1305 is the active cipher and use the alternate
framing path. This is the only cipher requiring special packet-level treatment;
all others use the standard format above.

### Key Exchange

Key exchange state machine flow:

1. Both sides send `SSH_MSG_KEXINIT` (algorithm negotiation)
2. Algorithm negotiation selects best mutually-supported set
3. Key exchange runs (e.g., Curve25519 DH)
4. Server sends host key + signature
5. Both sides derive session keys via hash
6. Both sides send `SSH_MSG_NEWKEYS`

Steps 3-5 are offloaded to a crypto worker. The session manages sequencing.

**Algorithm negotiation:** The selected algorithm is the first entry in the
client's list that also appears in the server's list (RFC 4253 section 7.1).
This is a pure function.

**Rekeying:** After `SSH_MSG_NEWKEYS`, the session swaps in new cipher/MAC
contexts atomically, consuming the old ones.

## Authentication Layer

### Client Side

`SshClientConfig` holds an ordered list of auth methods to try. The session
tries them in order, advancing on success, falling back on partial success,
failing on exhaustion.

### Server Side

Auth policy lives in the consumer. The consumer receives `ssh_auth_request`
with structured request data and responds with `auth_accept()` or
`auth_reject(remaining_methods)`.

### Supported Methods

- **none** — required by protocol; server responds with allowed methods list
- **publickey** — client signs challenge with private key; server verifies
- **password** — plaintext password (protected by transport encryption)

## Connection Layer

### Channel Multiplexing

`SshChannelManager` is a class (not actor) owned by the session. It:

- Maps local/remote channel IDs
- Tracks window sizes and enforces flow control
- Routes incoming data to the correct consumer

### Channel Lifecycle

1. Open request (either side) → session assigns local ID, sends
   `SSH_MSG_CHANNEL_OPEN`
2. Confirmation → channel state created in `SshChannelManager`, consumer
   notified with channel ID
3. Data flows bidirectionally via `session.channel_send(channel_id, data)`
4. Either side sends `SSH_MSG_CHANNEL_CLOSE` → session notifies consumer,
   channel state removed

The session handles `SSH_MSG_CHANNEL_WINDOW_ADJUST` transparently — consumers
do not manage flow control.

## Error Handling

Each package defines its own error vocabulary as a union type. Higher layers
wrap lower-layer errors to preserve full context.

### Crypto Errors

```pony
type SshCryptoError is
  ( SshDecryptFailed
  | SshMacMismatch
  | SshSignatureInvalid
  | SshKeyInvalid
  | SshOpenSSLError )
```

### Transport Errors

```pony
type SshTransportError is
  ( SshPacketTooLarge
  | SshPacketCorrupt
  | SshKexFailed val
  | SshAlgorithmNegotiationFailed
  | SshProtocolVersionMismatch
  | SshConnectionLost )
```

### Auth Errors

```pony
type SshAuthError is
  ( SshAuthRejected
  | SshAuthProtocolError
  | SshAuthCryptoError val )
```

### Channel Errors

```pony
type SshChannelError is
  ( SshChannelOpenFailed
  | SshChannelClosed
  | SshWindowExhausted )
```

Each error primitive implements `string(): String val`. Wrapping errors expose
the inner error for programmatic inspection.

**Consumer delivery:** The session translates internal errors into behaviors on
the consumer's notify interface (e.g., `ssh_disconnected(session, error)`).

**Protocol disconnects:** When SSH protocol requires `SSH_MSG_DISCONNECT`, the
session sends the message before transitioning to `SshStateDisconnected` and
notifying the consumer.

## Networking

Uses **lori** for TCP networking (not stdlib `net`).

**Integration with session actor:** `SshSession` wraps a lori `TCPConnection`.
The session actor implements lori's connection callbacks to receive raw bytes,
which it feeds into `SshPacketReader`. Outbound data from `SshPacketWriter` is
written to the lori connection.

**Server side:** `SshListener` wraps a lori `TCPListener`. On each accepted
connection, it creates a new `SshSession` actor with the accepted
`TCPConnection`.

**Client side:** `SshConnector` creates a lori `TCPConnection` to the target
host/port. On successful connect, it creates an `SshSession` actor with the
connection.

## Testing Strategy

### Property-Based Tests (PonyCheck) — Primary

**Crypto:**
- Roundtrip: `decrypt(encrypt(plaintext)) == plaintext` for all plaintexts
- MAC: `verify(compute(data, key), data, key) == true` for all data/keys;
  bit-flip in data or MAC causes failure
- Key exchange: both sides derive same shared secret for all keypairs
- Invalid inputs: truncated ciphertexts, wrong key sizes, corrupted MACs
  produce errors

**Packet framing:**
- Roundtrip: `read(write(payload)) == payload`
- Padding: packet length always multiple of block size, padding >= 4 bytes
- Boundaries: empty payload, max-size, block-size boundaries

**Algorithm negotiation:**
- Priority: result is first client preference supported by server
- No overlap: returns error
- Generator triad: valid/invalid/mixed preference lists

**State machine:**
- No valid message sequence from a given state reaches an illegal state
- Every valid message in a state produces exactly one defined transition

### Integration Tests (Example-Based) — Supplementary

- Full client-server handshake over loopback via lori
- Auth success and failure paths
- Channel open, data exchange, close
- Rekeying mid-session

### Counterfactual Checks

All new tests undergo counterfactual verification: temporarily break assertions
to confirm they fire, then revert.

## Dependencies

- **lori** — TCP networking
- **OpenSSL** (libssl, libcrypto) — cryptographic primitives via FFI
- **PonyCheck** (stdlib) — property-based testing
