use "lib:crypto"
use "lib:ssl"

// Cipher operations (EVP)
use @EVP_CIPHER_CTX_new[Pointer[None] tag]()
use @EVP_CIPHER_CTX_free[None](ctx: Pointer[None] tag)
use @EVP_EncryptInit_ex[I32](
  ctx: Pointer[None] tag,
  cipher: Pointer[None] tag,
  impl: Pointer[None] tag,
  key: Pointer[U8] tag,
  iv: Pointer[U8] tag)
use @EVP_EncryptUpdate[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  outl: Pointer[I32] tag,
  in': Pointer[U8] tag,
  inl: I32)
use @EVP_EncryptFinal_ex[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  outl: Pointer[I32] tag)
use @EVP_DecryptInit_ex[I32](
  ctx: Pointer[None] tag,
  cipher: Pointer[None] tag,
  impl: Pointer[None] tag,
  key: Pointer[U8] tag,
  iv: Pointer[U8] tag)
use @EVP_DecryptUpdate[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  outl: Pointer[I32] tag,
  in': Pointer[U8] tag,
  inl: I32)
use @EVP_DecryptFinal_ex[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  outl: Pointer[I32] tag)
use @EVP_CIPHER_CTX_ctrl[I32](
  ctx: Pointer[None] tag,
  type': I32,
  arg: I32,
  ptr: Pointer[None] tag)
use @EVP_CIPHER_CTX_set_padding[I32](ctx: Pointer[None] tag, padding: I32)
use @EVP_aes_256_gcm[Pointer[None] tag]()
use @EVP_aes_128_gcm[Pointer[None] tag]()
use @EVP_aes_256_ctr[Pointer[None] tag]()
use @EVP_aes_128_cbc[Pointer[None] tag]()
use @EVP_chacha20[Pointer[None] tag]()

// Poly1305 via the OpenSSL 3.0 EVP_MAC interface. Used to build the
// chacha20-poly1305@openssh.com AEAD by hand (OpenSSH's construction differs
// from the IETF EVP_chacha20_poly1305 AEAD: separate length key, length
// keystream at block counter 0, payload at counter 1, MAC over the raw
// encrypted length+payload).
use @EVP_MAC_fetch[Pointer[None] tag](
  libctx: Pointer[None] tag,
  algorithm: Pointer[U8] tag,
  properties: Pointer[U8] tag)
use @EVP_MAC_free[None](mac: Pointer[None] tag)
use @EVP_MAC_CTX_new[Pointer[None] tag](mac: Pointer[None] tag)
use @EVP_MAC_CTX_free[None](ctx: Pointer[None] tag)
use @EVP_MAC_init[I32](
  ctx: Pointer[None] tag,
  key: Pointer[U8] tag,
  keylen: USize,
  params: Pointer[None] tag)
use @EVP_MAC_update[I32](
  ctx: Pointer[None] tag,
  data: Pointer[U8] tag,
  datalen: USize)
use @EVP_MAC_final[I32](
  ctx: Pointer[None] tag,
  out: Pointer[U8] tag,
  outl: Pointer[USize] tag,
  outsize: USize)

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

// Message digest
use @EVP_DigestInit_ex[I32](
  ctx: Pointer[None] tag,
  type': Pointer[None] tag,
  impl: Pointer[None] tag)
use @EVP_DigestUpdate[I32](
  ctx: Pointer[None] tag,
  d: Pointer[U8] tag,
  cnt: USize)
use @EVP_DigestFinal_ex[I32](
  ctx: Pointer[None] tag,
  md: Pointer[U8] tag,
  s: Pointer[U32] tag)

// Key exchange (EVP_PKEY)
use @EVP_PKEY_CTX_new_id[Pointer[None] tag](id: I32, e: Pointer[None] tag)
use @EVP_PKEY_keygen_init[I32](ctx: Pointer[None] tag)
use @EVP_PKEY_keygen[I32](
  ctx: Pointer[None] tag,
  ppkey: Pointer[Pointer[None] tag] tag)
use @EVP_PKEY_CTX_new[Pointer[None] tag](
  pkey: Pointer[None] tag,
  e: Pointer[None] tag)
use @EVP_PKEY_derive_init[I32](ctx: Pointer[None] tag)
use @EVP_PKEY_derive_set_peer[I32](
  ctx: Pointer[None] tag,
  peer: Pointer[None] tag)
use @EVP_PKEY_derive[I32](
  ctx: Pointer[None] tag,
  key: Pointer[U8] tag,
  keylen: Pointer[USize] tag)
use @EVP_PKEY_free[None](pkey: Pointer[None] tag)
use @EVP_PKEY_CTX_free[None](ctx: Pointer[None] tag)
use @EVP_PKEY_new_raw_public_key[Pointer[None] tag](
  type': I32,
  e: Pointer[None] tag,
  key: Pointer[U8] tag,
  keylen: USize)
use @EVP_PKEY_new_raw_private_key[Pointer[None] tag](
  type': I32,
  e: Pointer[None] tag,
  key: Pointer[U8] tag,
  keylen: USize)
use @EVP_PKEY_get_raw_public_key[I32](
  pkey: Pointer[None] tag,
  pub: Pointer[U8] tag,
  len: Pointer[USize] tag)

// Signing and verification
use @EVP_DigestSignInit[I32](
  ctx: Pointer[None] tag,
  pctx: Pointer[Pointer[None] tag] tag,
  type': Pointer[None] tag,
  e: Pointer[None] tag,
  pkey: Pointer[None] tag)
use @EVP_DigestSign[I32](
  ctx: Pointer[None] tag,
  sigret: Pointer[U8] tag,
  siglen: Pointer[USize] tag,
  tbs: Pointer[U8] tag,
  tbslen: USize)
use @EVP_DigestVerifyInit[I32](
  ctx: Pointer[None] tag,
  pctx: Pointer[Pointer[None] tag] tag,
  type': Pointer[None] tag,
  e: Pointer[None] tag,
  pkey: Pointer[None] tag)
use @EVP_DigestVerify[I32](
  ctx: Pointer[None] tag,
  sigret: Pointer[U8] tag,
  siglen: USize,
  tbs: Pointer[U8] tag,
  tbslen: USize)
use @EVP_MD_CTX_new[Pointer[None] tag]()
use @EVP_MD_CTX_free[None](ctx: Pointer[None] tag)

// PEM key loading
use @PEM_read_bio_PrivateKey[Pointer[None] tag](
  bp: Pointer[None] tag,
  x: Pointer[Pointer[None] tag] tag,
  cb: Pointer[None] tag,
  u: Pointer[None] tag)
use @PEM_read_bio_PUBKEY[Pointer[None] tag](
  bp: Pointer[None] tag,
  x: Pointer[Pointer[None] tag] tag,
  cb: Pointer[None] tag,
  u: Pointer[None] tag)
use @BIO_new_mem_buf[Pointer[None] tag](buf: Pointer[U8] tag, len: I32)
use @BIO_free[I32](a: Pointer[None] tag)

// Random
use @RAND_bytes[I32](buf: Pointer[U8] tag, num: I32)

// Error handling
use @ERR_get_error[U64]()
use @ERR_error_string[Pointer[U8] tag](e: U64, buf: Pointer[U8] tag)

// Big number (for DH)
use @BN_new[Pointer[None] tag]()
use @BN_free[None](a: Pointer[None] tag)
use @BN_bin2bn[Pointer[None] tag](
  s: Pointer[U8] tag,
  len: I32,
  ret: Pointer[None] tag)
use @BN_bn2bin[I32](a: Pointer[None] tag, to: Pointer[U8] tag)
use @BN_num_bytes[I32](a: Pointer[None] tag)

// DH groups
use @DH_new[Pointer[None] tag]()
use @DH_free[None](dh: Pointer[None] tag)
use @DH_set0_pqg[I32](
  dh: Pointer[None] tag,
  p: Pointer[None] tag,
  q: Pointer[None] tag,
  g: Pointer[None] tag)
use @DH_generate_key[I32](dh: Pointer[None] tag)
use @DH_compute_key[I32](
  key: Pointer[U8] tag,
  pub_key: Pointer[None] tag,
  dh: Pointer[None] tag)
use @DH_get0_pub_key[Pointer[None] tag](dh: Pointer[None] tag)
use @DH_size[I32](dh: Pointer[None] tag)

// EC key operations
use @EC_KEY_new_by_curve_name[Pointer[None] tag](nid: I32)
use @EC_KEY_free[None](key: Pointer[None] tag)
use @EC_KEY_generate_key[I32](key: Pointer[None] tag)

// NID constants
primitive _NidX25519
  fun apply(): I32 => 1034

primitive _NidEd25519
  fun apply(): I32 => 1087

primitive _NidP256
  fun apply(): I32 => 415

primitive _EvpCtrlGcmSetIvlen
  fun apply(): I32 => 0x9

primitive _EvpCtrlGcmGetTag
  fun apply(): I32 => 0x10

primitive _EvpCtrlGcmSetTag
  fun apply(): I32 => 0x11
