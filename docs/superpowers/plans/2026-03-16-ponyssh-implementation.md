# ponyssh Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade SSH-2 client/server library for Pony with OpenSSL crypto, lori networking, and property-based tests.

**Architecture:** Hybrid session actor + crypto worker pattern. One `SshSession` actor per connection drives a protocol state machine (Handshake → KeyExchange → Auth → Connected → Disconnected). CPU-intensive key exchange is offloaded to worker actors; per-packet crypto runs inline. lori provides TCP; OpenSSL provides cryptographic primitives via FFI.

**Tech Stack:** Pony, lori (TCP), OpenSSL (FFI), PonyCheck (testing), corral (dependencies)

**Spec:** `docs/superpowers/specs/2026-03-16-ponyssh-design.md`

**Pony reference:** Use `/pony-ref` skill before each task for Pony language details (capabilities, PonyCheck patterns, stdlib pitfalls, FFI).

**lori API note:** lori requires the owning actor to implement `TCPConnectionActor` + a lifecycle receiver trait (`ClientLifecycleEventReceiver` or `ServerLifecycleEventReceiver`). These are `fun ref` callbacks on the actor, not a separate notify object. The spec's description of a "separate notify object" does not match lori's actual API. Instead, `SshSession` will be split into two internal actor types — `_SshClientSession` and `_SshServerSession` — that implement the appropriate lori traits. Both delegate to shared protocol logic (classes, not actors) for transport, auth, and connection handling.

---

## Chunk 1: Project Scaffolding + Error Types

### Task 1: Initialize project structure

**Files:**
- Create: `corral.json`
- Create: `Makefile`
- Create: `ponyssh/ssh_error/ssh_error.pony`
- Create: `ponyssh/ssh_test/_test.pony`

- [ ] **Step 1: Create corral.json**

```json
{
  "packages": [
    "ponyssh/ssh_error",
    "ponyssh/ssh_test"
  ],
  "deps": [
    {
      "locator": "github.com/ponylang/lori.git",
      "version": "0.10.0"
    }
  ],
  "info": {
    "description": "Production-grade SSH-2 client/server library for Pony",
    "license": "BSD-2-Clause",
    "version": "0.1.0",
    "name": "ponyssh"
  }
}
```

Note: Add packages to the `packages` array as they are created throughout the plan. Only `ssh_error` and `ssh_test` exist initially.

- [ ] **Step 2: Create Makefile**

```makefile
config ?= release

PACKAGE := ponyssh
GET_DEPENDENCIES_WITH := corral fetch
CLEAN_DEPENDENCIES_WITH := corral clean
COMPILE_WITH := corral run -- ponyc

BUILD_DIR ?= build/$(config)
SRC_DIR ?= ponyssh
tests_binary := $(BUILD_DIR)/ssh_test

ifdef config
	ifeq (,$(filter $(config),debug release))
		$(error Unknown configuration "$(config)")
	endif
endif

ifeq ($(config),release)
	PONYC = $(COMPILE_WITH)
else
	PONYC = $(COMPILE_WITH) --debug
endif

SOURCE_FILES := $(shell find $(SRC_DIR) -name *.pony)

test: unit-tests

unit-tests: $(tests_binary)
	$^ --sequential

$(tests_binary): $(SOURCE_FILES) | $(BUILD_DIR)
	$(GET_DEPENDENCIES_WITH)
	$(PONYC) -o $(BUILD_DIR) $(SRC_DIR)/ssh_test

clean:
	$(CLEAN_DEPENDENCIES_WITH)
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: clean test unit-tests
```

- [ ] **Step 3: Create ssh_error package with all error types from the spec**

File: `ponyssh/ssh_error/ssh_error.pony`

Define all error types per the spec. Leaf errors are primitives; wrapping errors are classes. All implement `Stringable`.

Crypto errors:
```pony
primitive SshDecryptFailed is Stringable
  fun string(): String iso^ => "decryption failed".clone()

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
  | SshMacMismatch
  | SshSignatureInvalid
  | SshKeyInvalid
  | SshOpenSSLError )
```

Transport errors:
```pony
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

type SshTransportError is
  ( SshPacketTooLarge
  | SshPacketCorrupt
  | SshKexFailed
  | SshAlgorithmNegotiationFailed
  | SshProtocolVersionMismatch
  | SshConnectionLost )
```

Auth errors:
```pony
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
```

Channel errors:
```pony
class val SshChannelOpenFailed is Stringable
  let reason_code: U32
  let description: String val
  new val create(reason_code': U32, description': String val) =>
    reason_code = reason_code'
    description = description'
  fun string(): String iso^ =>
    ("channel open failed (" + reason_code.string() + "): " + description).clone()

primitive SshChannelClosed is Stringable
  fun string(): String iso^ => "channel closed".clone()

primitive SshWindowExhausted is Stringable
  fun string(): String iso^ => "window exhausted".clone()

type SshChannelError is
  ( SshChannelOpenFailed
  | SshChannelClosed
  | SshWindowExhausted )
```

- [ ] **Step 4: Create minimal test runner**

File: `ponyssh/ssh_test/_test.pony`

```pony
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
```

- [ ] **Step 5: Fetch dependencies and verify build**

Run: `cd /home/red/projects/ponyssh && corral fetch`
Run: `make test`
Expected: Tests pass. One test: `ssh_error/error_strings`.

- [ ] **Step 6: Commit**

```bash
git add corral.json Makefile ponyssh/
git commit -m "feat: project scaffolding with error types and test runner"
```

---

## Chunk 2: Crypto Package — FFI Bindings + Ciphers

### Task 2: OpenSSL FFI declarations

**Files:**
- Create: `ponyssh/ssh_crypto/_ffi.pony`
- Create: `ponyssh/ssh_crypto/ssh_random.pony`

**Reference:** OpenSSL EVP API. The FFI layer declares raw C functions; wrappers in other files provide Pony-safe interfaces.

- [ ] **Step 1: Create FFI declarations**

File: `ponyssh/ssh_crypto/_ffi.pony`

```pony
use @EVP_CIPHER_CTX_new[Pointer[None] tag]()
use @EVP_CIPHER_CTX_free[None](ctx: Pointer[None] tag)
use @EVP_EncryptInit_ex[I32](
  ctx: Pointer[None] tag,
  cipher: Pointer[None] tag,
  engine: Pointer[None] tag,
  key: Pointer[U8] tag,
  iv: Pointer[U8] tag)
use @EVP_EncryptUpdate[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  out_len: Pointer[I32] tag,
  input: Pointer[U8] tag,
  in_len: I32)
use @EVP_EncryptFinal_ex[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  out_len: Pointer[I32] tag)
use @EVP_DecryptInit_ex[I32](
  ctx: Pointer[None] tag,
  cipher: Pointer[None] tag,
  engine: Pointer[None] tag,
  key: Pointer[U8] tag,
  iv: Pointer[U8] tag)
use @EVP_DecryptUpdate[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  out_len: Pointer[I32] tag,
  input: Pointer[U8] tag,
  in_len: I32)
use @EVP_DecryptFinal_ex[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  out_len: Pointer[I32] tag)
use @EVP_CIPHER_CTX_ctrl[I32](
  ctx: Pointer[None] tag,
  cmd: I32,
  p1: I32,
  p2: Pointer[U8] tag)
use @EVP_CIPHER_CTX_set_padding[I32](
  ctx: Pointer[None] tag,
  pad: I32)

// Cipher algorithm lookups
use @EVP_aes_256_gcm[Pointer[None] tag]()
use @EVP_aes_128_gcm[Pointer[None] tag]()
use @EVP_aes_256_ctr[Pointer[None] tag]()
use @EVP_aes_128_cbc[Pointer[None] tag]()
use @EVP_chacha20_poly1305[Pointer[None] tag]()

// HMAC
use @HMAC[Pointer[U8] tag](
  evp_md: Pointer[None] tag,
  key: Pointer[U8] tag,
  key_len: I32,
  data: Pointer[U8] tag,
  data_len: USize,
  md: Pointer[U8] tag,
  md_len: Pointer[U32] tag)
use @EVP_sha256[Pointer[None] tag]()
use @EVP_sha512[Pointer[None] tag]()

// Key exchange — EC and DH
use @EVP_PKEY_CTX_new_id[Pointer[None] tag](id: I32, engine: Pointer[None] tag)
use @EVP_PKEY_keygen_init[I32](ctx: Pointer[None] tag)
use @EVP_PKEY_keygen[I32](ctx: Pointer[None] tag, pkey: Pointer[Pointer[None] tag] tag)
use @EVP_PKEY_CTX_new[Pointer[None] tag](pkey: Pointer[None] tag, engine: Pointer[None] tag)
use @EVP_PKEY_derive_init[I32](ctx: Pointer[None] tag)
use @EVP_PKEY_derive_set_peer[I32](ctx: Pointer[None] tag, peer: Pointer[None] tag)
use @EVP_PKEY_derive[I32](ctx: Pointer[None] tag, key: Pointer[U8] tag, keylen: Pointer[USize] tag)
use @EVP_PKEY_free[None](pkey: Pointer[None] tag)
use @EVP_PKEY_CTX_free[None](ctx: Pointer[None] tag)
use @EVP_PKEY_new_raw_public_key[Pointer[None] tag](
  ptype: I32, engine: Pointer[None] tag,
  key: Pointer[U8] tag, keylen: USize)
use @EVP_PKEY_new_raw_private_key[Pointer[None] tag](
  ptype: I32, engine: Pointer[None] tag,
  key: Pointer[U8] tag, keylen: USize)
use @EVP_PKEY_get_raw_public_key[I32](
  pkey: Pointer[None] tag, pub_key: Pointer[U8] tag, len: Pointer[USize] tag)

// Signing/verification
use @EVP_DigestSignInit[I32](
  ctx: Pointer[None] tag,
  pctx: Pointer[Pointer[None] tag] tag,
  md: Pointer[None] tag,
  engine: Pointer[None] tag,
  pkey: Pointer[None] tag)
use @EVP_DigestSign[I32](
  ctx: Pointer[None] tag,
  sig: Pointer[U8] tag,
  siglen: Pointer[USize] tag,
  tbs: Pointer[U8] tag,
  tbslen: USize)
use @EVP_DigestVerifyInit[I32](
  ctx: Pointer[None] tag,
  pctx: Pointer[Pointer[None] tag] tag,
  md: Pointer[None] tag,
  engine: Pointer[None] tag,
  pkey: Pointer[None] tag)
use @EVP_DigestVerify[I32](
  ctx: Pointer[None] tag,
  sig: Pointer[U8] tag,
  siglen: USize,
  tbs: Pointer[U8] tag,
  tbslen: USize)
use @EVP_MD_CTX_new[Pointer[None] tag]()
use @EVP_MD_CTX_free[None](ctx: Pointer[None] tag)

// PEM key loading
use @PEM_read_bio_PrivateKey[Pointer[None] tag](
  bio: Pointer[None] tag,
  pkey: Pointer[Pointer[None] tag] tag,
  cb: Pointer[None] tag,
  u: Pointer[None] tag)
use @PEM_read_bio_PUBKEY[Pointer[None] tag](
  bio: Pointer[None] tag,
  pkey: Pointer[Pointer[None] tag] tag,
  cb: Pointer[None] tag,
  u: Pointer[None] tag)
use @BIO_new_mem_buf[Pointer[None] tag](buf: Pointer[U8] tag, len: I32)
use @BIO_free[I32](bio: Pointer[None] tag)

// Random
use @RAND_bytes[I32](buf: Pointer[U8] tag, num: I32)

// Error handling
use @ERR_get_error[U64]()
use @ERR_error_string[Pointer[U8]](e: U64, buf: Pointer[U8] tag)

// Big number (for DH)
use @BN_new[Pointer[None] tag]()
use @BN_free[None](bn: Pointer[None] tag)
use @BN_bin2bn[Pointer[None] tag](s: Pointer[U8] tag, len: I32, ret: Pointer[None] tag)
use @BN_bn2bin[I32](bn: Pointer[None] tag, to: Pointer[U8] tag)
use @BN_num_bytes[I32](bn: Pointer[None] tag)

// DH groups
use @DH_new[Pointer[None] tag]()
use @DH_free[None](dh: Pointer[None] tag)
use @DH_set0_pqg[I32](dh: Pointer[None] tag, p: Pointer[None] tag, q: Pointer[None] tag, g: Pointer[None] tag)
use @DH_generate_key[I32](dh: Pointer[None] tag)
use @DH_compute_key[I32](key: Pointer[U8] tag, pub_key: Pointer[None] tag, dh: Pointer[None] tag)
use @DH_get0_pub_key[None](dh: Pointer[None] tag, pub_key: Pointer[Pointer[None] tag] tag)
use @DH_size[I32](dh: Pointer[None] tag)

// EC key operations
use @EC_KEY_new_by_curve_name[Pointer[None] tag](nid: I32)
use @EC_KEY_free[None](key: Pointer[None] tag)
use @EC_KEY_generate_key[I32](key: Pointer[None] tag)

// EVP_PKEY NID constants (used with EVP_PKEY_CTX_new_id)
// NID_X25519 = 1034, NID_ED25519 = 1087
// NID_X9_62_prime256v1 = 415 (P-256)

// EVP_CTRL constants for GCM
// EVP_CTRL_GCM_SET_IVLEN = 0x9
// EVP_CTRL_GCM_GET_TAG = 0x10
// EVP_CTRL_GCM_SET_TAG = 0x11
```

Note: The exact FFI signatures may need adjustment during implementation based on the OpenSSL version installed. Verify against system headers. The NID and CTRL constants should be defined as Pony primitives for clarity.

- [ ] **Step 2: Create secure random wrapper**

File: `ponyssh/ssh_crypto/ssh_random.pony`

```pony
use "../ssh_error"

primitive SshRandom
  fun random_bytes(size: USize): Array[U8] iso^ =>
    """
    Generate cryptographically secure random bytes using OpenSSL RAND_bytes.
    """
    let buf = recover iso Array[U8].init(0, size) end
    let rc = @RAND_bytes(buf.cpointer(), size.i32())
    // RAND_bytes returns 1 on success. Failure means the CSPRNG is unseeded,
    // which is a system-level problem — no useful recovery is possible.
    ifdef debug then
      if rc != 1 then
        @fprintf[I32](@pony_os_stderr[Pointer[U8]](),
          "RAND_bytes failed\n".cpointer())
      end
    end
    consume buf
```

- [ ] **Step 3: Verify build compiles**

Run: `make config=debug 2>&1 | head -20`
Expected: Compiles without errors (no tests for _ffi.pony since it's just declarations).

- [ ] **Step 4: Commit**

```bash
git add ponyssh/ssh_crypto/
git commit -m "feat: OpenSSL FFI declarations and secure random wrapper"
```

### Task 3: Symmetric cipher wrappers

**Files:**
- Create: `ponyssh/ssh_crypto/ssh_cipher.pony`
- Create: `ponyssh/ssh_test/ssh_cipher_test.pony`

**Reference:** RFC 4253 section 6 for packet encryption; OpenSSL EVP_Encrypt*/EVP_Decrypt* API.

- [ ] **Step 1: Write cipher roundtrip property test**

File: `ponyssh/ssh_test/ssh_cipher_test.pony`

```pony
use "pony_test"
use "pony_check"
use "../ssh_crypto"
use "../ssh_error"

class iso _TestCipherRoundtrip is UnitTest
  """
  Property: decrypt(encrypt(plaintext, key, iv), key, iv) == plaintext
  for all generated plaintexts.
  """
  fun name(): String => "ssh_crypto/cipher_roundtrip"

  fun apply(h: TestHelper) ? =>
    // Test AES-256-GCM roundtrip
    let key = SshRandom.random_bytes(32)  // 256-bit key
    let iv = SshRandom.random_bytes(12)   // 96-bit IV for GCM

    PonyCheck.for_all[Array[U8] val](
      recover val Generators.array_of[U8](Generators.u8()) end, h)(
      {(plaintext: Array[U8] val, ph: PropertyHelper)(key, iv) =>
        let enc_ctx = SshCipherContext.aes_256_gcm(
          consume key.clone(), consume iv.clone(), true)?
        let enc_result = enc_ctx.encrypt(plaintext)

        let dec_ctx = SshCipherContext.aes_256_gcm(
          consume key.clone(), consume iv.clone(), false)?
        match enc_ctx.tag_value()
        | let tag: Array[U8] val =>
          dec_ctx.set_tag(tag)?
          match dec_ctx.decrypt(enc_result)
          | let decrypted: Array[U8] val =>
            ph.assert_array_eq[U8](plaintext, decrypted)
          | let err: SshCryptoError =>
            ph.fail("Decryption failed: " + err.string())
          end
        | None =>
          ph.fail("No GCM tag after encryption")
        end
      })?

class iso _TestCipherDecryptCorrupted is UnitTest
  """
  Property: flipping any byte in ciphertext causes decryption to fail.
  """
  fun name(): String => "ssh_crypto/cipher_decrypt_corrupted"

  fun apply(h: TestHelper) ? =>
    let key = SshRandom.random_bytes(32)
    let iv = SshRandom.random_bytes(12)
    let plaintext: Array[U8] val = SshRandom.random_bytes(64)

    let enc_ctx = SshCipherContext.aes_256_gcm(
      consume key.clone(), consume iv.clone(), true)?
    let ciphertext = enc_ctx.encrypt(plaintext)
    let tag = enc_ctx.tag_value() as Array[U8] val

    // Corrupt one byte
    if ciphertext.size() > 0 then
      let corrupted = recover iso
        let c = Array[U8].create(ciphertext.size())
        for byte in ciphertext.values() do c.push(byte) end
        try c(0)? = c(0)? xor 0xFF end
        c
      end

      let dec_ctx = SshCipherContext.aes_256_gcm(
        consume key.clone(), consume iv.clone(), false)?
      dec_ctx.set_tag(tag)?
      match dec_ctx.decrypt(consume corrupted)
      | let _: Array[U8] val =>
        h.fail("Decryption should have failed on corrupted ciphertext")
      | let _: SshCryptoError =>
        h.assert_true(true)  // Expected failure
      end
    end
```

Register tests in `_test.pony`: add `test(_TestCipherRoundtrip)` and `test(_TestCipherDecryptCorrupted)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test`
Expected: Compilation error — `SshCipherContext` not defined.

- [ ] **Step 3: Implement SshCipherContext**

File: `ponyssh/ssh_crypto/ssh_cipher.pony`

Implement `SshCipherContext` wrapping `EVP_CIPHER_CTX`. Key design:

```pony
use "../ssh_error"

interface val SshCipherAlgorithm
  fun name(): String
  fun key_len(): USize
  fun iv_len(): USize
  fun block_size(): USize
  fun is_aead(): Bool

primitive SshAes256Gcm is SshCipherAlgorithm
  fun name(): String => "aes256-gcm@openssh.com"
  fun key_len(): USize => 32
  fun iv_len(): USize => 12
  fun block_size(): USize => 16
  fun is_aead(): Bool => true

primitive SshAes128Gcm is SshCipherAlgorithm
  fun name(): String => "aes128-gcm@openssh.com"
  fun key_len(): USize => 16
  fun iv_len(): USize => 12
  fun block_size(): USize => 16
  fun is_aead(): Bool => true

primitive SshAes256Ctr is SshCipherAlgorithm
  fun name(): String => "aes256-ctr"
  fun key_len(): USize => 32
  fun iv_len(): USize => 16
  fun block_size(): USize => 16
  fun is_aead(): Bool => false

primitive SshAes128Cbc is SshCipherAlgorithm
  fun name(): String => "aes128-cbc"
  fun key_len(): USize => 16
  fun iv_len(): USize => 16
  fun block_size(): USize => 16
  fun is_aead(): Bool => false

primitive SshChacha20Poly1305 is SshCipherAlgorithm
  fun name(): String => "chacha20-poly1305@openssh.com"
  fun key_len(): USize => 64  // 2x 32-byte keys (main + header)
  fun iv_len(): USize => 0    // IV derived from sequence number
  fun block_size(): USize => 8
  fun is_aead(): Bool => true

class SshCipherContext
  var _ctx: Pointer[None] tag
  let _encrypting: Bool
  var _tag: (Array[U8] val | None) = None

  new aes_256_gcm(key: Array[U8] val, iv: Array[U8] val, encrypting: Bool) ? =>
    _encrypting = encrypting
    _ctx = @EVP_CIPHER_CTX_new()
    if _ctx.is_null() then error end
    _init(@EVP_aes_256_gcm(), key, iv)?

  new aes_128_gcm(key: Array[U8] val, iv: Array[U8] val, encrypting: Bool) ? =>
    _encrypting = encrypting
    _ctx = @EVP_CIPHER_CTX_new()
    if _ctx.is_null() then error end
    _init(@EVP_aes_128_gcm(), key, iv)?

  new aes_256_ctr(key: Array[U8] val, iv: Array[U8] val, encrypting: Bool) ? =>
    _encrypting = encrypting
    _ctx = @EVP_CIPHER_CTX_new()
    if _ctx.is_null() then error end
    _init(@EVP_aes_256_ctr(), key, iv)?

  new aes_128_cbc(key: Array[U8] val, iv: Array[U8] val, encrypting: Bool) ? =>
    _encrypting = encrypting
    _ctx = @EVP_CIPHER_CTX_new()
    if _ctx.is_null() then error end
    @EVP_CIPHER_CTX_set_padding(_ctx, 0)  // SSH handles its own padding
    _init(@EVP_aes_128_cbc(), key, iv)?

  fun ref _init(cipher: Pointer[None] tag, key: Array[U8] val, iv: Array[U8] val) ? =>
    let rc = if _encrypting then
      @EVP_EncryptInit_ex(_ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    else
      @EVP_DecryptInit_ex(_ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    end
    if rc != 1 then error end

  fun ref encrypt(plaintext: Array[U8] val, is_aead: Bool = true): Array[U8] val =>
    let out = recover iso Array[U8].init(0, plaintext.size() + 16) end
    var out_len: I32 = 0
    @EVP_EncryptUpdate(_ctx, out.cpointer(), addressof out_len,
      plaintext.cpointer(), plaintext.size().i32())
    out.truncate(out_len.usize())

    var final_len: I32 = 0
    let final_buf = recover iso Array[U8].init(0, 16) end
    @EVP_EncryptFinal_ex(_ctx, final_buf.cpointer(), addressof final_len)

    // Only extract GCM/AEAD tag for AEAD ciphers
    if is_aead then
      let tag = recover iso Array[U8].init(0, 16) end
      @EVP_CIPHER_CTX_ctrl(_ctx, 0x10, 16, tag.cpointer())
      _tag = consume tag
    end

    if final_len > 0 then
      let result = recover iso Array[U8].create(out_len.usize() + final_len.usize()) end
      result.copy_from(out, 0, 0, out_len.usize())
      result.copy_from(final_buf, 0, out_len.usize(), final_len.usize())
      result.truncate((out_len + final_len).usize())
      consume result
    else
      consume out
    end

  fun ref set_tag(tag: Array[U8] val) ? =>
    let rc = @EVP_CIPHER_CTX_ctrl(_ctx, 0x11, tag.size().i32(), tag.cpointer())
    if rc != 1 then error end

  fun tag_value(): (Array[U8] val | None) => _tag

  fun ref decrypt(ciphertext: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    let out = recover iso Array[U8].init(0, ciphertext.size() + 16) end
    var out_len: I32 = 0
    @EVP_DecryptUpdate(_ctx, out.cpointer(), addressof out_len,
      ciphertext.cpointer(), ciphertext.size().i32())

    var final_len: I32 = 0
    let final_buf = recover iso Array[U8].init(0, 16) end
    let rc = @EVP_DecryptFinal_ex(_ctx, final_buf.cpointer(), addressof final_len)
    if rc != 1 then
      return SshDecryptFailed
    end

    out.truncate(out_len.usize())
    consume out

  fun _final() =>
    if not _ctx.is_null() then
      @EVP_CIPHER_CTX_free(_ctx)
    end
```

Note: The chacha20-poly1305 cipher requires special handling (separate header encryption key derived from sequence number per the OpenSSH spec). Implement it as a separate class `SshChacha20Poly1305Context` rather than another constructor on `SshCipherContext`, since its encrypt/decrypt signatures differ (they take a sequence number).

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test`
Expected: `ssh_crypto/cipher_roundtrip` and `ssh_crypto/cipher_decrypt_corrupted` pass.

- [ ] **Step 5: Counterfactual check**

Temporarily change the roundtrip test assertion to compare against a different value (e.g., append a byte to `plaintext` before comparison). Run tests, confirm failure. Revert.

- [ ] **Step 6: Commit**

```bash
git add ponyssh/ssh_crypto/ssh_cipher.pony ponyssh/ssh_test/ssh_cipher_test.pony
git commit -m "feat: symmetric cipher wrappers with AES-GCM, AES-CTR, AES-CBC"
```

### Task 4: HMAC wrapper

**Files:**
- Create: `ponyssh/ssh_crypto/ssh_mac.pony`
- Modify: `ponyssh/ssh_test/ssh_cipher_test.pony` (add MAC tests)

- [ ] **Step 1: Write MAC property tests**

Add to test file:
- Roundtrip: `verify(compute(data, key), data, key) == true` for all data/keys
- Bit-flip: flipping any bit in data or MAC causes verify to fail

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement SshMac**

```pony
use "../ssh_error"

interface val SshMacAlgorithm
  fun name(): String
  fun key_len(): USize
  fun digest_len(): USize

primitive SshHmacSha256 is SshMacAlgorithm
  fun name(): String => "hmac-sha2-256"
  fun key_len(): USize => 32
  fun digest_len(): USize => 32

primitive SshHmacSha512 is SshMacAlgorithm
  fun name(): String => "hmac-sha2-512"
  fun key_len(): USize => 64
  fun digest_len(): USize => 64

primitive SshMac
  fun compute_sha256(key: Array[U8] val, data: Array[U8] val): Array[U8] val =>
    _compute(@EVP_sha256(), key, data, 32)

  fun compute_sha512(key: Array[U8] val, data: Array[U8] val): Array[U8] val =>
    _compute(@EVP_sha512(), key, data, 64)

  fun verify(expected: Array[U8] val, computed: Array[U8] val): Bool =>
    // Constant-time comparison to prevent timing attacks
    if expected.size() != computed.size() then return false end
    var result: U8 = 0
    try
      var i: USize = 0
      while i < expected.size() do
        result = result or (expected(i)? xor computed(i)?)
        i = i + 1
      end
    end
    result == 0

  fun _compute(md: Pointer[None] tag, key: Array[U8] val,
    data: Array[U8] val, digest_size: USize): Array[U8] val
  =>
    let out = recover iso Array[U8].init(0, digest_size) end
    var out_len: U32 = 0
    @HMAC(md, key.cpointer(), key.size().i32(),
      data.cpointer(), data.size(), out.cpointer(), addressof out_len)
    out.truncate(out_len.usize())
    consume out
```

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check on MAC verify**
- [ ] **Step 6: Commit**

```bash
git add ponyssh/ssh_crypto/ssh_mac.pony ponyssh/ssh_test/
git commit -m "feat: HMAC-SHA256 and HMAC-SHA512 wrappers"
```

### Task 5: Key exchange primitives

**Files:**
- Create: `ponyssh/ssh_crypto/ssh_kex.pony`
- Modify: `ponyssh/ssh_test/` (add kex tests)

**Reference:** RFC 5656 (ECDH), RFC 8731 (Curve25519), RFC 4253 section 8 (DH).

- [ ] **Step 1: Write key exchange property test**

Property: For all generated keypairs, both sides derive the same shared secret.

Generate a keypair for each side, exchange public keys, derive shared secret independently, assert equality.

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement key exchange primitives**

Implement for each algorithm:
- `SshKexCurve25519` — uses `EVP_PKEY` with `NID_X25519`
- `SshKexEcdhP256` — uses `EC_KEY` with `NID_X9_62_prime256v1`
- `SshKexDhGroup14` — uses `DH` with RFC 3526 group 14 parameters
- `SshKexDhGroup16` — uses `DH` with RFC 3526 group 16 parameters

Implement Curve25519 first (simplest, modern, most common), then follow the same pattern for the others:

```pony
class SshKexCurve25519
  """X25519 key exchange using EVP_PKEY with NID_X25519 (1034)."""
  let _pkey: Pointer[None] tag

  new create() ? =>
    let ctx = @EVP_PKEY_CTX_new_id(1034, Pointer[None])  // NID_X25519
    if ctx.is_null() then error end
    if @EVP_PKEY_keygen_init(ctx) != 1 then
      @EVP_PKEY_CTX_free(ctx)
      error
    end
    var pkey: Pointer[None] tag = Pointer[None]
    if @EVP_PKEY_keygen(ctx, addressof pkey) != 1 then
      @EVP_PKEY_CTX_free(ctx)
      error
    end
    @EVP_PKEY_CTX_free(ctx)
    _pkey = pkey

  fun public_key(): Array[U8] val =>
    let buf = recover iso Array[U8].init(0, 32) end
    var len: USize = 32
    @EVP_PKEY_get_raw_public_key(_pkey, buf.cpointer(), addressof len)
    buf.truncate(len)
    consume buf

  fun derive_shared_secret(peer_public: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    let peer_pkey = @EVP_PKEY_new_raw_public_key(1034, Pointer[None],
      peer_public.cpointer(), peer_public.size())
    if peer_pkey.is_null() then return SshKeyInvalid end

    let ctx = @EVP_PKEY_CTX_new(_pkey, Pointer[None])
    if ctx.is_null() then
      @EVP_PKEY_free(peer_pkey)
      return SshKeyInvalid
    end

    if @EVP_PKEY_derive_init(ctx) != 1 then
      @EVP_PKEY_CTX_free(ctx)
      @EVP_PKEY_free(peer_pkey)
      return SshDecryptFailed
    end

    if @EVP_PKEY_derive_set_peer(ctx, peer_pkey) != 1 then
      @EVP_PKEY_CTX_free(ctx)
      @EVP_PKEY_free(peer_pkey)
      return SshKeyInvalid
    end

    var secret_len: USize = 0
    @EVP_PKEY_derive(ctx, Pointer[U8], addressof secret_len)  // get length
    let secret = recover iso Array[U8].init(0, secret_len) end
    @EVP_PKEY_derive(ctx, secret.cpointer(), addressof secret_len)
    secret.truncate(secret_len)

    @EVP_PKEY_CTX_free(ctx)
    @EVP_PKEY_free(peer_pkey)
    consume secret

  fun _final() =>
    if not _pkey.is_null() then @EVP_PKEY_free(_pkey) end
```

For the remaining algorithms, follow the same three-method pattern (`create`, `public_key`, `derive_shared_secret`):

- `SshKexEcdhP256`: Uses `EVP_PKEY_CTX_new_id` with `NID_X9_62_prime256v1` (415). Public key is the EC point in uncompressed form. Shared secret derivation uses the same `EVP_PKEY_derive` API.
- `SshKexDhGroup14`: Uses `DH_new` + `DH_set0_pqg` with RFC 3526 group 14 prime (2048-bit). Generate with `DH_generate_key`, exchange via `DH_compute_key`. Public key is the big-endian encoding of the DH public value.
- `SshKexDhGroup16`: Same as DhGroup14 but with RFC 3526 group 16 prime (4096-bit).

The DH groups require hardcoded prime values from RFC 3526. Store them as hex string constants and convert via `BN_bin2bn`.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: key exchange primitives (Curve25519, ECDH-P256, DH-14, DH-16)"
```

### Task 6: Host key operations

**Files:**
- Create: `ponyssh/ssh_crypto/ssh_hostkey.pony`
- Modify: `ponyssh/ssh_test/` (add hostkey tests)

**Reference:** RFC 8709 (Ed25519), RFC 5656 (ECDSA), RFC 8332 (RSA-SHA2).

- [ ] **Step 1: Write signing/verification property test**

Property: `verify(sign(data, private_key), data, public_key) == true` for all data.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement host key types**

```pony
use "../ssh_error"

class val SshHostKey
  """Holds a public key and its algorithm name."""
  let algorithm: String val
  let public_key_data: Array[U8] val
  new val create(algorithm': String val, public_key_data': Array[U8] val) =>
    algorithm = algorithm'
    public_key_data = public_key_data'

class val SshHostKeyPair
  """Holds both private and public key material."""
  let algorithm: String val
  let _pkey: Pointer[None] tag  // EVP_PKEY

  new val from_pem(data: Array[U8] val) ? =>
    """Parse PEM private key, determine algorithm from key type."""
    let bio = @BIO_new_mem_buf(data.cpointer(), data.size().i32())
    if bio.is_null() then error end
    let pkey = @PEM_read_bio_PrivateKey(bio, Pointer[Pointer[None] tag],
      Pointer[None], Pointer[None])
    @BIO_free(bio)
    if pkey.is_null() then error end
    _pkey = pkey
    // Determine algorithm from EVP_PKEY type
    // EVP_PKEY_id(_pkey) returns NID: ED25519=1087, EC=408, RSA=6
    // Map to SSH algorithm name accordingly
    algorithm = _detect_algorithm(pkey)

  fun _detect_algorithm(pkey: Pointer[None] tag): String val =>
    // Use @EVP_PKEY_id to get the NID, map to SSH algorithm name
    // NID 1087 -> "ssh-ed25519"
    // NID 408 (EC) -> "ecdsa-sha2-nistp256" (check curve)
    // NID 6 (RSA) -> "rsa-sha2-256"
    "ssh-ed25519"  // placeholder — implement NID dispatch

  fun sign(data: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    """Sign data using EVP_DigestSign."""
    let md_ctx = @EVP_MD_CTX_new()
    if md_ctx.is_null() then return SshKeyInvalid end

    // For Ed25519: md is None (EdDSA handles its own hashing)
    // For ECDSA/RSA: md is EVP_sha256() or EVP_sha512()
    let md: Pointer[None] tag = Pointer[None]  // Ed25519 case
    var pctx: Pointer[None] tag = Pointer[None]
    if @EVP_DigestSignInit(md_ctx, addressof pctx, md, Pointer[None], _pkey) != 1 then
      @EVP_MD_CTX_free(md_ctx)
      return SshKeyInvalid
    end

    // Get signature length
    var sig_len: USize = 0
    @EVP_DigestSign(md_ctx, Pointer[U8], addressof sig_len,
      data.cpointer(), data.size())

    // Perform signing
    let sig = recover iso Array[U8].init(0, sig_len) end
    let rc = @EVP_DigestSign(md_ctx, sig.cpointer(), addressof sig_len,
      data.cpointer(), data.size())
    @EVP_MD_CTX_free(md_ctx)

    if rc != 1 then return SshSignatureInvalid end
    sig.truncate(sig_len)
    consume sig

  fun public_key(): SshHostKey =>
    """Extract public key bytes."""
    let buf = recover iso Array[U8].init(0, 256) end
    var len: USize = 256
    @EVP_PKEY_get_raw_public_key(_pkey, buf.cpointer(), addressof len)
    buf.truncate(len)
    SshHostKey(algorithm, consume buf)

  fun _final() =>
    if not _pkey.is_null() then @EVP_PKEY_free(_pkey) end

primitive SshHostKeyVerify
  fun verify(key: SshHostKey val, signature: Array[U8] val,
    data: Array[U8] val): (Bool | SshCryptoError)
  =>
    """Verify signature using EVP_DigestVerify."""
    // Load public key from raw bytes
    // For Ed25519: EVP_PKEY_new_raw_public_key(NID_ED25519, ...)
    // For ECDSA: need to reconstruct EC_KEY from point encoding
    // For RSA: need to parse from SSH wire format
    let pkey = match key.algorithm
    | "ssh-ed25519" =>
      @EVP_PKEY_new_raw_public_key(1087, Pointer[None],
        key.public_key_data.cpointer(), key.public_key_data.size())
    else
      return SshKeyInvalid  // unknown algorithm
    end
    if pkey.is_null() then return SshKeyInvalid end

    let md_ctx = @EVP_MD_CTX_new()
    if md_ctx.is_null() then
      @EVP_PKEY_free(pkey)
      return SshKeyInvalid
    end

    var pctx: Pointer[None] tag = Pointer[None]
    let md: Pointer[None] tag = Pointer[None]  // Ed25519 case
    if @EVP_DigestVerifyInit(md_ctx, addressof pctx, md, Pointer[None], pkey) != 1 then
      @EVP_MD_CTX_free(md_ctx)
      @EVP_PKEY_free(pkey)
      return SshSignatureInvalid
    end

    let rc = @EVP_DigestVerify(md_ctx, signature.cpointer(), signature.size(),
      data.cpointer(), data.size())
    @EVP_MD_CTX_free(md_ctx)
    @EVP_PKEY_free(pkey)

    if rc == 1 then true
    else SshSignatureInvalid
    end
```

Implement Ed25519 first (simplest — no hash parameter needed). Then add ECDSA-P256 (needs `EVP_sha256()` as the md parameter and EC key reconstruction from point encoding) and RSA-SHA2 (needs `EVP_sha256()`/`EVP_sha512()` and RSA key parsing from SSH wire format). Each additional algorithm extends the `match` in `verify` and `_detect_algorithm`.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: host key signing and verification (Ed25519, ECDSA, RSA)"
```

---

## Chunk 3: Transport Layer — Packet Framing + Algorithm Negotiation

### Task 7: SSH binary packet framing (plaintext)

**Files:**
- Create: `ponyssh/ssh_transport/ssh_packet.pony`
- Create: `ponyssh/ssh_test/ssh_packet_test.pony`

**Reference:** RFC 4253 section 6.

- [ ] **Step 1: Write packet roundtrip property test**

Property: `read(write(payload)) == payload` for all payloads 0..32768 bytes.

```pony
class iso _TestPacketRoundtrip is UnitTest
  fun name(): String => "ssh_transport/packet_roundtrip_plaintext"

  fun apply(h: TestHelper) ? =>
    PonyCheck.for_all[Array[U8] val](
      recover val Generators.array_of[U8](Generators.u8()) end, h)(
      {(payload: Array[U8] val, ph: PropertyHelper) =>
        let writer = SshPacketWriter.plaintext()
        let packet = writer.write(payload, 8)  // 8-byte block alignment

        let reader = SshPacketReader.plaintext()
        reader.append(packet)
        match reader.read()
        | let result: Array[U8] val =>
          ph.assert_array_eq[U8](payload, result)
        | let err: SshTransportError =>
          ph.fail("Read failed: " + err.string())
        | None =>
          ph.fail("Incomplete packet")
        end
      })?
```

Also test:
- Padding is always >= 4 bytes and < 256 bytes
- Total packet length (excluding MAC) is multiple of block size (8 for plaintext)
- Packets > 35000 bytes are rejected

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement SshPacketWriter and SshPacketReader**

`SshPacketWriter`:
- `write(payload, block_size)` → `Array[U8] iso^`
- Computes padding: `4 + block_size - ((5 + payload.size() + 4) % block_size)`
  ensuring minimum 4 bytes padding
- Writes: `[packet_length(4) | padding_length(1) | payload | random_padding]`
- Tracks send sequence number (U32), increments after each write

`SshPacketReader`:
- `append(data: Array[U8] val)` — buffers incoming bytes
- `read()` → `(Array[U8] val | SshTransportError | None)` — returns payload, error, or None if incomplete
- Reads packet_length first (4 bytes), validates <= 35000, reads remaining bytes
- Tracks receive sequence number (U32), increments after each read
- Returns `SshPacketTooLarge` for oversized packets

Both classes are `ref` — owned by the session actor.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check** — change block_size assertion, verify failure
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: SSH binary packet framing (plaintext mode)"
```

### Task 8: Encrypted packet framing

**Files:**
- Modify: `ponyssh/ssh_transport/ssh_packet.pony`
- Modify: `ponyssh/ssh_test/ssh_packet_test.pony`

- [ ] **Step 1: Write encrypted roundtrip property test**

Same roundtrip property but with cipher contexts installed. Test with AES-256-GCM.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Add encryption support to writer/reader**

`SshPacketWriter`:
- Add `fun ref set_cipher(cipher: SshCipherContext, mac: (SshMacAlgorithm | None))`
- When cipher is set, encrypt the packet after framing
- For AEAD ciphers: no separate MAC
- For non-AEAD: append HMAC(key, sequence_number || unencrypted_packet)

`SshPacketReader`:
- Add `fun ref set_cipher(cipher: SshCipherContext, mac: (SshMacAlgorithm | None), mac_key: Array[U8] val)`
- When cipher is set, decrypt before extracting payload
- For AEAD: verify authentication tag during decryption
- For non-AEAD: verify HMAC, return `SshMacMismatch` on failure

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: encrypted packet framing with AEAD and HMAC"
```

### Task 9: Algorithm negotiation

**Files:**
- Create: `ponyssh/ssh_transport/ssh_algorithms.pony`
- Create: `ponyssh/ssh_test/ssh_algorithms_test.pony`

**Reference:** RFC 4253 section 7.1.

- [ ] **Step 1: Write algorithm negotiation property tests**

Generator triad approach:

Valid generator: produces arrays of known algorithm names, at least 1 element.
Invalid generator: empty arrays, arrays of unknown names.

Properties:
- Result is always the first entry in client's list that server also supports
- Empty client or server list → `SshAlgorithmNegotiationFailed`
- No overlap → `SshAlgorithmNegotiationFailed`
- If both lists are identical, result is the first element

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement algorithm negotiation**

```pony
use "../ssh_error"

class val SshAlgorithmPreferences
  """Ordered preference lists for each algorithm category."""
  let kex: Array[String val] val
  let host_key: Array[String val] val
  let cipher_client_to_server: Array[String val] val
  let cipher_server_to_client: Array[String val] val
  let mac_client_to_server: Array[String val] val
  let mac_server_to_client: Array[String val] val
  // ... constructor

class val SshNegotiatedAlgorithms
  """Result of negotiation — one algorithm per category."""
  let kex: String val
  let host_key: String val
  let cipher_c2s: String val
  let cipher_s2c: String val
  let mac_c2s: String val
  let mac_s2c: String val
  // ... constructor

primitive SshAlgorithmNegotiation
  fun negotiate(client: SshAlgorithmPreferences val,
    server: SshAlgorithmPreferences val):
    (SshNegotiatedAlgorithms val | SshAlgorithmNegotiationFailed)
  =>
    """First client preference that server also supports, per category."""
    // For each category, find first match
    ...

  fun _negotiate_one(client_prefs: Array[String val] val,
    server_prefs: Array[String val] val): (String val | None)
  =>
    for c in client_prefs.values() do
      for s in server_prefs.values() do
        if c == s then return c end
      end
    end
    None
```

Also define default preference orders:
```pony
primitive SshDefaultAlgorithms
  fun preferences(): SshAlgorithmPreferences val =>
    // Modern-first ordering
    SshAlgorithmPreferences(where
      kex' = ["curve25519-sha256"; "ecdh-sha2-nistp256";
              "diffie-hellman-group16-sha512";
              "diffie-hellman-group14-sha256"],
      host_key' = ["ssh-ed25519"; "ecdsa-sha2-nistp256";
                   "rsa-sha2-512"; "rsa-sha2-256"],
      cipher_client_to_server' = ["chacha20-poly1305@openssh.com";
        "aes256-gcm@openssh.com"; "aes128-gcm@openssh.com";
        "aes256-ctr"; "aes128-cbc"],
      cipher_server_to_client' = ["chacha20-poly1305@openssh.com";
        "aes256-gcm@openssh.com"; "aes128-gcm@openssh.com";
        "aes256-ctr"; "aes128-cbc"],
      mac_client_to_server' = ["hmac-sha2-256"; "hmac-sha2-512"],
      mac_server_to_client' = ["hmac-sha2-256"; "hmac-sha2-512"])
```

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: algorithm negotiation with default modern-first preferences"
```

### Task 10: SSH_MSG_KEXINIT message encoding/decoding

**Files:**
- Create: `ponyssh/ssh_transport/ssh_messages.pony`
- Modify: `ponyssh/ssh_test/` (add message tests)

**Reference:** RFC 4253 section 7.1 — KEXINIT message format.

- [ ] **Step 1: Write KEXINIT roundtrip property test**

Property: `decode(encode(kexinit)) == kexinit` for generated preference lists.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement SSH message encoding/decoding**

Start with SSH wire types: `SshWireReader` and `SshWireWriter` for reading/writing SSH wire format primitives (byte, uint32, string, name-list, mpint) per RFC 4251 section 5.

Then implement KEXINIT encode/decode on top.

Split wire primitives from message codecs for maintainability:

- `ponyssh/ssh_transport/ssh_wire.pony` — `SshWireReader` and `SshWireWriter` for SSH wire format primitives (byte, uint32, string, name-list, mpint per RFC 4251 section 5). These are reused by all message codecs.
- `ponyssh/ssh_transport/ssh_messages.pony` — Transport-layer messages: `SSH_MSG_KEXINIT` (20), `SSH_MSG_NEWKEYS` (21), `SSH_MSG_DISCONNECT` (1), `SSH_MSG_SERVICE_REQUEST` (5), `SSH_MSG_SERVICE_ACCEPT` (6).

Auth messages (Task 13) go in `ponyssh/ssh_auth/ssh_auth_messages.pony`.
Channel messages (Task 14) go in `ponyssh/ssh_connection/ssh_channel_messages.pony`.

This keeps each file focused on one protocol layer's messages.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: SSH wire format primitives and KEXINIT message codec"
```

---

## Chunk 4: Key Exchange State Machine + Auth Layer

### Task 11: Session state types

**Files:**
- Create: `ponyssh/ssh_transport/ssh_state.pony`

- [ ] **Step 1: Define state types**

```pony
use "../ssh_error"
use "../ssh_crypto"

type SshSessionState is
  ( SshStateHandshake
  | SshStateKeyExchange
  | SshStateAuth
  | SshStateConnected
  | SshStateDisconnected )

class SshStateHandshake
  """Waiting for version exchange."""
  var remote_version: (String val | None) = None

class SshStateKeyExchange
  """Key exchange in progress."""
  let our_kexinit: Array[U8] val       // Our KEXINIT payload (needed for hash)
  let their_kexinit: Array[U8] val     // Their KEXINIT payload
  let negotiated: SshNegotiatedAlgorithms val
  var shared_secret: (Array[U8] val | None) = None
  var exchange_hash: (Array[U8] val | None) = None
  // ... constructor

class SshStateAuth
  """Authentication in progress."""
  let session_id: Array[U8] val
  var methods_remaining: Array[String val] val
  // ... constructor

class SshStateConnected
  """Fully authenticated, channels active."""
  let session_id: Array[U8] val
  var rekeying: Bool = false
  var rekey_outbound_queue: Array[Array[U8] val] = Array[Array[U8] val]
  // ... constructor

class SshStateDisconnected
  """Terminal state."""
  let reason: (SshTransportError | None)
  new create(reason': (SshTransportError | None) = None) =>
    reason = reason'
```

- [ ] **Step 2: Define SshSessionContext**

```pony
class SshSessionContext
  var remote_addr: String val = ""
  var remote_version: (String val | None) = None
  var negotiated_algorithms: (SshNegotiatedAlgorithms val | None) = None
  var authenticated_as: (String val | None) = None
  var session_id: (Array[U8] val | None) = None
  var server_host_key: (SshHostKey val | None) = None
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: session state machine types and context"
```

### Task 12: Key exchange state machine

**Files:**
- Create: `ponyssh/ssh_transport/ssh_kexstate.pony`
- Modify: `ponyssh/ssh_test/` (add kex state tests)

**Reference:** RFC 4253 sections 7-8.

- [ ] **Step 1: Write state transition tests**

Test that:
- Valid message sequences produce expected state transitions
- Invalid messages in a given state produce errors
- Both client and server roles follow the correct flow

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement SshKexStateMachine**

This is a class (not actor) that encapsulates key exchange logic. The session actor calls its methods synchronously.

```pony
primitive SshRoleClient
primitive SshRoleServer
type SshRole is (SshRoleClient | SshRoleServer)

class SshKexStateMachine
  let _role: SshRole

  new create(role: SshRole) =>
    _role = role

  fun ref generate_kexinit(prefs: SshAlgorithmPreferences val): Array[U8] val =>
    """Generate our SSH_MSG_KEXINIT payload."""
    ...

  fun ref receive_kexinit(their_payload: Array[U8] val,
    our_prefs: SshAlgorithmPreferences val):
    (SshNegotiatedAlgorithms val | SshTransportError)
  =>
    """Parse their KEXINIT, negotiate algorithms."""
    ...

  fun ref derive_keys(shared_secret: Array[U8] val,
    exchange_hash: Array[U8] val, session_id: Array[U8] val,
    negotiated: SshNegotiatedAlgorithms val):
    SshDerivedKeys val
  =>
    """Derive encryption keys per RFC 4253 section 7.2."""
    // K1 = HASH(K || H || "A" || session_id) — IV client to server
    // K2 = HASH(K || H || "B" || session_id) — IV server to client
    // K3 = HASH(K || H || "C" || session_id) — encryption key c2s
    // K4 = HASH(K || H || "D" || session_id) — encryption key s2c
    // K5 = HASH(K || H || "E" || session_id) — MAC key c2s
    // K6 = HASH(K || H || "F" || session_id) — MAC key s2c
    ...

class val SshDerivedKeys
  let iv_c2s: Array[U8] val
  let iv_s2c: Array[U8] val
  let enc_key_c2s: Array[U8] val
  let enc_key_s2c: Array[U8] val
  let mac_key_c2s: Array[U8] val
  let mac_key_s2c: Array[U8] val
```

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Counterfactual check**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: key exchange state machine with key derivation"
```

### Task 13: Auth messages and state machine

**Files:**
- Create: `ponyssh/ssh_auth/ssh_auth.pony`
- Create: `ponyssh/ssh_auth/ssh_password.pony`
- Create: `ponyssh/ssh_auth/ssh_publickey.pony`
- Create: `ponyssh/ssh_auth/ssh_none.pony`
- Modify: `ponyssh/ssh_transport/ssh_messages.pony` (add auth messages)
- Modify: `ponyssh/ssh_test/` (add auth tests)

**Reference:** RFC 4252.

- [ ] **Step 1: Add auth message types to ssh_messages.pony**

Add encode/decode for:
- `SSH_MSG_USERAUTH_REQUEST` (50)
- `SSH_MSG_USERAUTH_FAILURE` (51)
- `SSH_MSG_USERAUTH_SUCCESS` (52)
- `SSH_MSG_USERAUTH_BANNER` (53)

- [ ] **Step 2: Write auth state machine tests**

Test client-side: tries methods in order, handles rejection, stops on success.
Test server-side: dispatches auth requests to consumer, handles accept/reject.

- [ ] **Step 3: Run to verify failure**

- [ ] **Step 4: Implement auth state machine**

```pony
use "../ssh_error"
use "../ssh_crypto"

class val SshAuthRequest
  """Structured auth request for server consumer."""
  let username: String val
  let method: String val
  let method_data: SshAuthMethodData val

type SshAuthMethodData is
  ( SshAuthPasswordData
  | SshAuthPublicKeyData
  | SshAuthNoneData )

class val SshAuthPasswordData
  let password: String val

class val SshAuthPublicKeyData
  let algorithm: String val
  let public_key: Array[U8] val
  let signature: (Array[U8] val | None)  // None for query, Some for actual auth

primitive SshAuthNoneData

class SshAuthStateMachine
  """Client-side auth state machine."""
  let _methods: Array[SshAuthMethod val] val
  var _current_index: USize = 0
  var _username: String val

  new create(username: String val, methods: Array[SshAuthMethod val] val) =>
    _username = username
    _methods = methods

  fun ref next_request(session_id: Array[U8] val):
    (Array[U8] val | SshAuthError)
  =>
    """Generate the next SSH_MSG_USERAUTH_REQUEST payload."""
    ...

  fun ref handle_failure(methods_allowed: Array[String val] val):
    (Array[U8] val | SshAuthError | SshAuthRejected)
  =>
    """Handle SSH_MSG_USERAUTH_FAILURE. Try next method or fail."""
    ...
```

- [ ] **Step 5: Run tests, verify pass**
- [ ] **Step 6: Counterfactual check**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat: authentication layer with none, password, publickey methods"
```

---

## Chunk 5: Connection Layer + Session Actor

### Task 14: Channel management

**Files:**
- Create: `ponyssh/ssh_connection/ssh_channel.pony`
- Create: `ponyssh/ssh_connection/ssh_manager.pony`
- Modify: `ponyssh/ssh_transport/ssh_messages.pony` (add channel messages)
- Modify: `ponyssh/ssh_test/` (add channel tests)

**Reference:** RFC 4254 sections 5-6.

- [ ] **Step 1: Add channel message types**

File: `ponyssh/ssh_connection/ssh_channel_messages.pony`

Add encode/decode for:
- `SSH_MSG_CHANNEL_OPEN` (90)
- `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (91)
- `SSH_MSG_CHANNEL_OPEN_FAILURE` (92)
- `SSH_MSG_CHANNEL_WINDOW_ADJUST` (93)
- `SSH_MSG_CHANNEL_DATA` (94)
- `SSH_MSG_CHANNEL_EOF` (96)
- `SSH_MSG_CHANNEL_CLOSE` (97)

Note: EOF is distinct from CLOSE per RFC 4254 section 5.3. EOF signals "no more data from this direction" while CLOSE tears down the channel. The session should send EOF before CLOSE for clean shutdown.

- [ ] **Step 2: Write channel manager tests**

Test:
- Open channel: assigns sequential local IDs
- Map local/remote IDs correctly
- Window tracking: data send decreases window, adjust increases it
- `SshWindowExhausted` when window is 0
- Close removes channel state

- [ ] **Step 3: Run to verify failure**

- [ ] **Step 4: Implement channel state and manager**

```pony
use "../ssh_error"

class SshChannelState
  let local_id: U32
  var remote_id: U32
  var local_window: U32
  var remote_window: U32
  var max_packet_size: U32
  let channel_type: String val
  var open: Bool = true

class SshChannelManager
  var _next_local_id: U32 = 0
  let _channels: Map[U32, SshChannelState] = Map[U32, SshChannelState]

  fun ref open_channel(channel_type: String val): U32 =>
    """Allocate local channel ID and create pending state."""
    let id = _next_local_id = _next_local_id + 1
    _channels(id) = SshChannelState(id, 0, 0x200000, 0, 0, channel_type)
    id

  fun ref confirm_channel(local_id: U32, remote_id: U32,
    remote_window: U32, max_packet_size: U32): (None | SshChannelError)
  =>
    ...

  fun ref channel_data_send(local_id: U32, data_size: USize):
    (U32 | SshChannelError)
  =>
    """Check window, return remote channel ID. Caller handles framing."""
    ...

  fun ref channel_data_received(local_id: U32, data_size: USize) =>
    """Decrease local window after receiving data."""
    ...

  fun ref window_adjust(local_id: U32, bytes: U32) =>
    """Increase remote window for channel."""
    ...

  fun ref close_channel(local_id: U32) =>
    """Remove channel state."""
    ...

  fun ref find_by_remote_id(remote_id: U32): (U32 | None) =>
    """Find local ID for a remote channel ID."""
    ...
```

- [ ] **Step 5: Run tests, verify pass**
- [ ] **Step 6: Counterfactual check**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat: channel management with flow control"
```

### Task 15: Session actor — client side

**Files:**
- Create: `ponyssh/ssh_transport/ssh_session.pony`
- Create: `ponyssh/ssh_transport/_ssh_tcp_bridge.pony`
- Create: `ponyssh/ssh_client/ssh_connector.pony`

**Reference:** Spec sections on Architecture, Public API, Networking.

This is the integration task — wiring transport, auth, connection, and lori together.

- [ ] **Step 1: Define notify interfaces**

File: `ponyssh/ssh_transport/ssh_notify.pony` (separate file to keep session actor focused)

```pony
use "lori"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_connection"

interface SshClientNotify
  be ssh_verify_host_key(session: SshSession tag, host: String val, key: SshHostKey val)
  be ssh_ready(session: SshSession tag)
  be ssh_auth_failed(session: SshSession tag, error: SshAuthError val)
  be ssh_channel_opened(session: SshSession tag, channel_id: U32)
  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val)
  be ssh_channel_error(session: SshSession tag, channel_id: U32, error: SshChannelError val)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32)
  be ssh_error(session: SshSession tag, error: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)

interface SshServerNotify
  be ssh_session_started(session: SshSession tag)
  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val)
  be ssh_session_ready(session: SshSession tag)
  be ssh_channel_open_request(session: SshSession tag, channel_id: U32, channel_type: String val)
  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val)
  be ssh_channel_error(session: SshSession tag, channel_id: U32, error: SshChannelError val)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32)
  be ssh_error(session: SshSession tag, error: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)
```

- [ ] **Step 2: Implement TCP bridge actor**

File: `ponyssh/ssh_transport/_ssh_tcp_bridge.pony`

The bridge actor implements lori's `TCPConnectionActor` + `ClientLifecycleEventReceiver` (or `ServerLifecycleEventReceiver`) and forwards events to `SshSession`.

```pony
use "lori"

actor _SshClientTcpBridge is (TCPConnectionActor & ClientLifecycleEventReceiver)
  var _conn: TCPConnection
  let _session: SshSession tag

  new create(auth: TCPConnectAuth, host: String, port: String,
    session: SshSession tag)
  =>
    _session = session
    _conn = TCPConnection.client(auth, host, port, "", this, this)

  fun ref _connection(): TCPConnection => _conn

  fun ref _on_connected() =>
    _session._tcp_connected()

  fun ref _on_connection_failure(reason: ConnectionFailureReason) =>
    _session._tcp_connection_failed()

  fun ref _on_received(data: Array[U8] iso) =>
    _session._tcp_received(consume data)

  fun ref _on_closed() =>
    _session._tcp_closed()

  be write(data: ByteSeq) =>
    _conn.send(data)

  be close() =>
    _conn.close()

actor _SshServerTcpBridge is (TCPConnectionActor & ServerLifecycleEventReceiver)
  var _conn: TCPConnection
  let _session: SshSession tag

  new create(auth: TCPServerAuth, fd: U32, session: SshSession tag) =>
    _session = session
    _conn = TCPConnection.server(auth, fd, this, this)

  fun ref _connection(): TCPConnection => _conn

  fun ref _on_started() =>
    _session._tcp_connected()

  fun ref _on_received(data: Array[U8] iso) =>
    _session._tcp_received(consume data)

  fun ref _on_closed() =>
    _session._tcp_closed()

  be write(data: ByteSeq) =>
    _conn.send(data)

  be close() =>
    _conn.close()
```

- [ ] **Step 3: Implement SshSession actor**

File: `ponyssh/ssh_transport/ssh_session.pony`

This is the core actor. It holds all the protocol state and classes:

```pony
use "lori"
use "../ssh_error"
use "../ssh_crypto"
use "../ssh_auth"
use "../ssh_connection"

type SshNotify is (SshClientNotify | SshServerNotify)

actor SshSession
  let _role: SshRole
  let _notify: SshNotify
  let _config: (SshClientConfig val | SshServerConfig val)
  let _bridge: (_SshClientTcpBridge tag | _SshServerTcpBridge tag)
  var _state: SshSessionState
  let _context: SshSessionContext = SshSessionContext
  let _reader: SshPacketReader = SshPacketReader.plaintext()
  let _writer: SshPacketWriter = SshPacketWriter.plaintext()
  let _channel_manager: SshChannelManager = SshChannelManager
  var _kex: (SshKexStateMachine | None) = None
  var _auth: (SshAuthStateMachine | None) = None

  // --- Public behaviors (called by consumers) ---

  be open_channel(channel_type: String val) =>
    """Consumer requests a new channel."""
    match _state
    | let s: SshStateConnected =>
      let local_id = _channel_manager.open_channel(channel_type)
      // Encode and send SSH_MSG_CHANNEL_OPEN
      _send_packet(SshMessages.channel_open(local_id, channel_type, 0x200000, 0x8000))
    end

  be channel_send(channel_id: U32, data: Array[U8] val) =>
    """Consumer sends data on a channel."""
    match _state
    | let s: SshStateConnected =>
      match _channel_manager.channel_data_send(channel_id, data.size())
      | let remote_id: U32 =>
        _send_packet(SshMessages.channel_data(remote_id, data))
      | let err: SshChannelError =>
        _notify_channel_error(channel_id, err)
      end
    end

  be channel_close(channel_id: U32) =>
    ...

  be accept_host_key() =>
    """Consumer accepts the server's host key."""
    // Resume key exchange
    ...

  be reject_host_key() =>
    """Consumer rejects the server's host key."""
    _disconnect(SshProtocolVersionMismatch)

  be auth_accept() =>
    """Server consumer accepts auth."""
    ...

  be auth_reject(remaining: Array[String val] val) =>
    """Server consumer rejects auth."""
    ...

  be accept_channel(channel_id: U32) =>
    ...

  be reject_channel(channel_id: U32, reason: U32) =>
    ...

  // --- Internal behaviors (called by TCP bridge) ---

  be _tcp_connected() =>
    """TCP connection established. Send version string."""
    _send_version()

  be _tcp_received(data: Array[U8] iso) =>
    """Raw bytes from TCP. Feed to packet reader."""
    _reader.append(consume data)
    _process_packets()

  be _tcp_closed() =>
    _transition(SshStateDisconnected(SshConnectionLost))

  be _tcp_connection_failed() =>
    _transition(SshStateDisconnected(SshConnectionLost))

  // --- Internal behaviors (called by crypto workers) ---

  be _kex_computed(shared_secret: Array[U8] iso, exchange_hash: Array[U8] iso) =>
    """Crypto worker completed key exchange computation."""
    ...

  // --- Private methods ---

  fun ref _process_packets() =>
    """Read and dispatch packets from the reader."""
    while true do
      match _reader.read()
      | let payload: Array[U8] val => _dispatch_packet(payload)
      | let err: SshTransportError => _disconnect_with_error(err)
      | None => return  // Need more data
      end
    end

  fun ref _dispatch_packet(payload: Array[U8] val) =>
    """Route a decrypted payload to the appropriate handler based on state."""
    try
      let msg_type = payload(0)?
      match _state
      | let _: SshStateHandshake => _handle_handshake(msg_type, payload)
      | let _: SshStateKeyExchange => _handle_kex(msg_type, payload)
      | let _: SshStateAuth => _handle_auth(msg_type, payload)
      | let _: SshStateConnected => _handle_connected(msg_type, payload)
      | let _: SshStateDisconnected => None  // Ignore
      end
    end

  fun ref _send_packet(payload: Array[U8] val) =>
    """Frame and send a packet."""
    let block_size: USize = _current_block_size()  // 8 for plaintext, cipher's block_size when encrypted
    let packet = _writer.write(payload, block_size)
    _bridge.write(consume packet)

  fun ref _disconnect_with_error(err: SshTransportError) =>
    """Send SSH_MSG_DISCONNECT and transition to Disconnected."""
    let payload = SshMessages.disconnect(
      SshDisconnectCodes.protocol_error(), err.string())
    _send_packet(payload)
    _bridge.close()
    _transition(SshStateDisconnected(err))

  fun ref _transition(new_state: SshSessionState) =>
    """Transition to a new state and notify consumer."""
    _state = new_state
    match new_state
    | let s: SshStateDisconnected =>
      match s.reason
      | let err: SshTransportError =>
        match _notify
        | let n: SshClientNotify => n.ssh_error(this, err)
        | let n: SshServerNotify => n.ssh_error(this, err)
        end
      end
      match _notify
      | let n: SshClientNotify => n.ssh_disconnected(this)
      | let n: SshServerNotify => n.ssh_disconnected(this)
      end
    | let _: SshStateConnected =>
      match _notify
      | let n: SshClientNotify => n.ssh_ready(this)
      | let n: SshServerNotify => n.ssh_session_ready(this)
      end
    end
```

This is the largest single implementation. The message handlers (`_handle_handshake`, `_handle_kex`, `_handle_auth`, `_handle_connected`) each follow the protocol flow:

- `_handle_handshake`: Parse version string, send our version, transition to KeyExchange
- `_handle_kex`: Drive KEXINIT exchange, dispatch crypto worker, handle NEWKEYS
- `_handle_auth`: Client: send auth requests. Server: forward to consumer.
- `_handle_connected`: Route channel messages, handle rekey requests

- [ ] **Step 4: Implement SshConnector**

File: `ponyssh/ssh_client/ssh_connector.pony`

```pony
use "lori"
use "../ssh_transport"

class val SshClientConfig
  let host: String val
  let port: String val
  let auth_methods: Array[SshAuthMethod val] val
  let algorithms: (SshAlgorithmPreferences val | None)
  // ... constructor with named parameters

type SshAuthMethod is (SshPublicKeyAuth | SshPasswordAuth | SshNoneAuth)

class val SshPublicKeyAuth
  let private_key_data: Array[U8] val
  new val create(private_key_data': Array[U8] val) =>
    private_key_data = private_key_data'

class val SshPasswordAuth
  let password: String val
  new val create(password': String val) =>
    password = password'

primitive SshNoneAuth

primitive SshConnector
  fun connect(auth: TCPConnectAuth, config: SshClientConfig val,
    notify: SshClientNotify): SshSession tag
  =>
    """Create an SSH client session."""
    SshSession._client(auth, config, notify)
```

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: session actor, TCP bridge, and client connector"
```

### Task 16: Session actor — server side

**Files:**
- Create: `ponyssh/ssh_server/ssh_listener.pony`
- Modify: `ponyssh/ssh_transport/_ssh_tcp_bridge.pony` (complete server bridge)

- [ ] **Step 1: Implement SshListener**

```pony
use "lori"
use "../ssh_transport"

class val SshServerConfig
  let host_keys: Array[SshHostKeyPair val] val
  let listen_host: String val
  let listen_port: String val
  let algorithms: (SshAlgorithmPreferences val | None)
  // ... constructor

actor SshListener is TCPListenerActor
  var _listener: TCPListener
  let _config: SshServerConfig val
  let _notify: SshServerNotify

  new create(auth: TCPListenAuth, config: SshServerConfig val,
    notify: SshServerNotify)
  =>
    _config = config
    _notify = notify
    _listener = TCPListener(auth, config.listen_host, config.listen_port, this)

  fun ref _listener(): TCPListener => _listener

  fun ref _on_accept(fd: U32): _SshServerTcpBridge ? =>
    let session = SshSession._server(_config, _notify)
    _SshServerTcpBridge(fd, session)

  fun ref _on_listening() => None
  fun ref _on_listen_failure() => None
  fun ref _on_closed() => None
```

- [ ] **Step 2: Wire SshListener._on_accept to create server sessions**

In `_on_accept(fd)`:
1. Create `TCPServerAuth` from the listen auth
2. Create a new `SshSession` via `SshSession._server(_config, _notify)`
3. Create `_SshServerTcpBridge(auth, fd, session)`
4. Call `_notify.ssh_session_started(session)`
5. Return the bridge

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: SSH server listener"
```

---

## Chunk 6: Crypto Worker + Integration Tests

### Task 17: Crypto worker actor

**Files:**
- Create: `ponyssh/ssh_transport/_ssh_crypto_worker.pony`
- Modify: `ponyssh/ssh_transport/ssh_session.pony` (dispatch to worker)

- [ ] **Step 1: Implement crypto worker**

```pony
use "../ssh_crypto"

actor _SshKexWorker
  """
  Short-lived actor for CPU-intensive key exchange computation.
  Sends result back to session via iso.
  """
  let _session: SshSession tag

  new create(session: SshSession tag, algorithm: String val,
    peer_public: Array[U8] val, our_kexinit: Array[U8] val,
    their_kexinit: Array[U8] val, /* ... other kex params */)
  =>
    _session = session
    _compute(algorithm, peer_public, our_kexinit, their_kexinit)

  be _compute(algorithm: String val, peer_public: Array[U8] val,
    our_kexinit: Array[U8] val, their_kexinit: Array[U8] val)
  =>
    // Perform ECDH/DH computation
    // Compute exchange hash
    // Send results back to session
    match algorithm
    | "curve25519-sha256" =>
      try
        let kex = SshKexCurve25519.create()?
        match kex.derive_shared_secret(peer_public)
        | let secret: Array[U8] val =>
          let hash = _compute_exchange_hash(secret, our_kexinit, their_kexinit)
          _session._kex_computed(secret, hash)
        | let err: SshCryptoError =>
          _session._kex_failed(SshKexFailed(err))
        end
      else
        _session._kex_failed(SshKexFailed(SshKeyInvalid))
      end
    | "ecdh-sha2-nistp256" =>
      // Same pattern with SshKexEcdhP256
      _do_kex_ecdh_p256(peer_public, our_kexinit, their_kexinit)
    | "diffie-hellman-group14-sha256" =>
      _do_kex_dh(peer_public, our_kexinit, their_kexinit, 14)
    | "diffie-hellman-group16-sha512" =>
      _do_kex_dh(peer_public, our_kexinit, their_kexinit, 16)
    else
      // Unreachable after negotiation, but handle defensively
      _session._kex_failed(SshKexFailed(SshKeyInvalid))
    end
```

- [ ] **Step 2: Wire worker dispatch into session**

In `SshSession._handle_kex`, after receiving the peer's public key, create an `_SshKexWorker` instead of computing inline.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: crypto worker actor for key exchange offloading"
```

### Task 18: Integration tests

**Files:**
- Create: `ponyssh/ssh_test/ssh_integration_test.pony`

**Reference:** Spec testing strategy section.

- [ ] **Step 1: Write loopback handshake test**

Test a full client-server handshake over localhost:
- Start SshListener on a random port
- Connect SshConnector to it
- Verify both sides reach `ssh_ready` / `ssh_session_ready`
- Open a channel, send data, verify receipt
- Close channel, disconnect

```pony
class iso _TestLoopbackHandshake is UnitTest
  fun name(): String => "integration/loopback_handshake"

  fun apply(h: TestHelper) =>
    h.long_test(5_000_000_000)  // 5 second timeout

    // Generate test host key
    // Create server config with test key
    // Create client config with accept-all host key verifier
    // Start listener
    // Connect client
    // Verify handshake completes via notify callbacks
    // h.complete(true) in ssh_ready callback
    ...
```

- [ ] **Step 2: Write auth success/failure tests**

Two tests:
- **Auth success**: Client uses password auth, server consumer accepts in `ssh_auth_request`. Verify client receives `ssh_ready`, server receives `ssh_session_ready`.
- **Auth failure**: Client uses wrong password, server consumer rejects. Verify client receives `ssh_auth_failed`. If all methods exhausted, verify `ssh_disconnected` fires on both sides.

- [ ] **Step 3: Write channel data exchange test**

Scenario: After successful handshake, client opens a `"session"` channel. Server accepts in `ssh_channel_open_request`. Client sends `b"hello"` via `session.channel_send`. Server receives it in `ssh_channel_data` and echoes it back. Client receives echo in `ssh_channel_data`. Client closes channel. Both sides receive `ssh_channel_closed`.

Expected: Data arrives intact on both sides. Channel IDs are consistent.

- [ ] **Step 4: Write rekeying test**

Scenario: After successful handshake with an open channel, client sends enough data to trigger the 1 GB threshold (or call an internal `_initiate_rekey` behavior for testing). Verify: data continues to flow during and after rekeying, both sides transition through `Rekeying` sub-state and back to `Connected`, no data is lost or corrupted. Test by sending data before, during, and after rekey and verifying all of it arrives.
- [ ] **Step 5: Run all tests**

Run: `make test`
Expected: All tests pass.

- [ ] **Step 6: Counterfactual checks on integration tests**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat: integration tests — handshake, auth, channels, rekeying"
```

### Task 19: chacha20-poly1305 special handling

**Files:**
- Create: `ponyssh/ssh_crypto/ssh_chacha20poly1305.pony`
- Modify: `ponyssh/ssh_transport/ssh_packet.pony` (alternate framing path)
- Modify: `ponyssh/ssh_test/` (add chacha20 tests)

**Reference:** OpenSSH chacha20-poly1305 spec, RFC 4253 section 6.

- [ ] **Step 1: Write chacha20-poly1305 roundtrip test**

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement SshChacha20Poly1305Context**

This cipher uses two ChaCha20 instances:
- Header key: encrypts the 4-byte packet length field
- Main key: encrypts payload + padding, with Poly1305 MAC
- Both use the sequence number as nonce

```pony
class SshChacha20Poly1305Context
  """
  OpenSSH's chacha20-poly1305@openssh.com cipher.
  Requires 64 bytes of key material (two 32-byte keys).
  IV is derived from the packet sequence number.
  """
  fun ref encrypt(sequence_number: U32, plaintext: Array[U8] val,
    packet_length: U32): Array[U8] iso^
  =>
    // 1. Encrypt packet_length with header key + sequence number as nonce
    // 2. Encrypt payload+padding with main key + sequence number as nonce
    // 3. Compute Poly1305 tag over encrypted length + encrypted payload
    ...

  fun ref decrypt(sequence_number: U32, data: Array[U8] val):
    (Array[U8] iso^ | SshCryptoError)
  =>
    // 1. Decrypt packet_length with header key
    // 2. Verify Poly1305 tag
    // 3. Decrypt payload with main key
    ...
```

- [ ] **Step 4: Add alternate framing path to SshPacketReader/Writer**

When chacha20-poly1305 is active, delegate to `SshChacha20Poly1305Context` instead of the standard encrypt-after-frame path.

- [ ] **Step 5: Run tests, verify pass**
- [ ] **Step 6: Counterfactual check**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat: chacha20-poly1305@openssh.com cipher with packet framing"
```

### Task 20: Final cleanup and update corral.json

- [ ] **Step 1: Ensure all packages are listed in corral.json**

Update the `packages` array to include all created packages:
```json
"packages": [
  "ponyssh/ssh_error",
  "ponyssh/ssh_crypto",
  "ponyssh/ssh_transport",
  "ponyssh/ssh_auth",
  "ponyssh/ssh_connection",
  "ponyssh/ssh_client",
  "ponyssh/ssh_server",
  "ponyssh/ssh_test"
]
```

- [ ] **Step 2: Run full test suite**

Run: `make test`
Expected: All tests pass.

- [ ] **Step 3: Final commit**

```bash
git add corral.json
git commit -m "chore: ensure all packages registered in corral.json"
```
