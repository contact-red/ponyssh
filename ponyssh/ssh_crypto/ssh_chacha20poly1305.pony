use "../ssh_error"

class SshChacha20Poly1305Context
  """
  chacha20-poly1305@openssh.com, implemented per OpenSSH's
  PROTOCOL.chacha20poly1305 — which is NOT the IETF RFC 8439 AEAD that OpenSSL's
  EVP_chacha20_poly1305 provides. The differences (all on the wire, so they must
  match OpenSSH exactly):

  * Two independent ChaCha20 keys. K_2 (the first 32 bytes of key material)
    encrypts the payload; K_1 (the second 32 bytes) encrypts the 4-byte packet
    length as a standalone stream.
  * The nonce is the packet sequence number as a big-endian uint64.
  * The length field is encrypted with K_1 at block counter 0. The payload is
    encrypted with K_2 at block counter 1 — block counter 0 of K_2 produces the
    one-time Poly1305 key.
  * Poly1305 authenticates the raw bytes (encrypted_length || encrypted_payload)
    with no AEAD framing.

  Built from raw EVP_chacha20 (for keystream/counter control) plus a standalone
  Poly1305 (EVP_MAC), since the EVP AEAD cannot express this layout.
  """
  let _main_key: Array[U8] val    // K_2: key_material[0, 32)  — payload
  let _header_key: Array[U8] val  // K_1: key_material[32, 64) — length
  var _poly_mac: Pointer[None] tag  // fetched EVP_MAC for POLY1305

  new create(key_material: Array[U8] val) ? =>
    """Key material must be 64 bytes: K_2 (0-31) || K_1 (32-63)."""
    if key_material.size() != 64 then error end
    _main_key = key_material.trim(0, 32)
    _header_key = key_material.trim(32, 64)
    _poly_mac = @EVP_MAC_fetch(Pointer[None], "POLY1305".cstring(), Pointer[U8])
    if _poly_mac.is_null() then error end

  fun _final() =>
    if not _poly_mac.is_null() then @EVP_MAC_free(_poly_mac) end

  fun _iv(sequence_number: U32, counter: U8): Array[U8] val =>
    """
    The 16-byte IV OpenSSL's EVP_chacha20 expects (block counter as a 32-bit
    little-endian word, then a 96-bit nonce), arranged to reproduce OpenSSH's
    64-bit-counter / 64-bit-nonce ChaCha20 state: counter in byte 0, the
    sequence number as a big-endian uint64 occupying the final 8 bytes (its top
    4 bytes are zero because the sequence number is 32-bit).
    """
    recover val
      let v = Array[U8].init(0, 16)
      try
        v(0)? = counter
        v(12)? = (sequence_number >> 24).u8()
        v(13)? = (sequence_number >> 16).u8()
        v(14)? = (sequence_number >> 8).u8()
        v(15)? = sequence_number.u8()
      end
      v
    end

  fun _chacha20(key: Array[U8] val, iv: Array[U8] val, data: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Raw ChaCha20 keystream applied to data. ChaCha20 is a stream cipher, so
    this is its own inverse — the same call both encrypts and decrypts.
    """
    let ctx = @EVP_CIPHER_CTX_new()
    if ctx.is_null() then return SshDecryptFailed end
    let result =
      if @EVP_EncryptInit_ex(ctx, @EVP_chacha20(), Pointer[None],
        key.cpointer(), iv.cpointer()) != 1
      then
        SshDecryptFailed
      else
        let out = recover iso Array[U8].init(0, data.size()) end
        var out_len: I32 = 0
        if @EVP_EncryptUpdate(ctx, out.cpointer(), addressof out_len,
          data.cpointer(), data.size().i32()) != 1
        then
          SshDecryptFailed
        else
          out.truncate(out_len.usize())
          consume out
        end
      end
    @EVP_CIPHER_CTX_free(ctx)
    result

  fun _poly1305(key: Array[U8] val, data: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """Poly1305 tag (16 bytes) over data, keyed by the one-time key."""
    let ctx = @EVP_MAC_CTX_new(_poly_mac)
    if ctx.is_null() then return SshDecryptFailed end
    let result =
      if @EVP_MAC_init(ctx, key.cpointer(), key.size(), Pointer[None]) != 1 then
        SshDecryptFailed
      elseif @EVP_MAC_update(ctx, data.cpointer(), data.size()) != 1 then
        SshDecryptFailed
      else
        let out = recover iso Array[U8].init(0, 16) end
        var out_len: USize = 0
        if @EVP_MAC_final(ctx, out.cpointer(), addressof out_len, 16) != 1 then
          SshDecryptFailed
        else
          out.truncate(out_len)
          consume out
        end
      end
    @EVP_MAC_CTX_free(ctx)
    result

  fun _poly_key(sequence_number: U32): (Array[U8] val | SshCryptoError) =>
    """The one-time Poly1305 key: K_2 keystream block 0, first 32 bytes."""
    _chacha20(_main_key, _iv(sequence_number, 0), recover val Array[U8].init(0, 32) end)

  fun ref encrypt(sequence_number: U32, plaintext_packet: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Encrypt a complete SSH packet (packet_length(4) || padding_length || payload
    || padding). Returns encrypted_length(4) || encrypted_payload || tag(16).
    """
    if plaintext_packet.size() < 5 then return SshEncryptFailed end
    let length_plain = plaintext_packet.trim(0, 4)
    let body_plain = plaintext_packet.trim(4)

    let poly_key = match _poly_key(sequence_number)
      | let k: Array[U8] val => k
      | let e: SshCryptoError => return e
      end
    let enc_length = match _chacha20(_header_key, _iv(sequence_number, 0),
      length_plain)
      | let c: Array[U8] val => c
      | let e: SshCryptoError => return e
      end
    let enc_body = match _chacha20(_main_key, _iv(sequence_number, 1), body_plain)
      | let c: Array[U8] val => c
      | let e: SshCryptoError => return e
      end

    let ciphertext = recover val
      let c = Array[U8].create(enc_length.size() + enc_body.size())
      c.append(enc_length)
      c.append(enc_body)
      c
    end
    let poly_tag = match _poly1305(poly_key, ciphertext)
      | let t: Array[U8] val => t
      | let e: SshCryptoError => return e
      end

    recover val
      let r = Array[U8].create(ciphertext.size() + poly_tag.size())
      r.append(ciphertext)
      r.append(poly_tag)
      r
    end

  fun ref decrypt(sequence_number: U32, data: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Decrypt a chacha20-poly1305 packet: encrypted_length(4) ||
    encrypted_payload(N) || tag(16). Returns packet_length(4) ||
    padding_length || payload || padding. Verifies the tag before decrypting.
    """
    if data.size() < 20 then return SshDecryptFailed end  // 4 + 0 + 16 minimum
    let ciphertext = data.trim(0, data.size() - 16)
    let received_tag = data.trim(data.size() - 16)

    // Authenticate before decrypting (encrypt-then-MAC).
    let poly_key = match _poly_key(sequence_number)
      | let k: Array[U8] val => k
      | let e: SshCryptoError => return e
      end
    let expected_tag = match _poly1305(poly_key, ciphertext)
      | let t: Array[U8] val => t
      | let e: SshCryptoError => return e
      end
    if not SshMac.verify(received_tag, expected_tag) then
      return SshMacMismatch
    end

    let enc_length = data.trim(0, 4)
    let dec_length = match _chacha20(_header_key, _iv(sequence_number, 0),
      enc_length)
      | let c: Array[U8] val => c
      | let e: SshCryptoError => return e
      end
    let packet_length =
      try
        (dec_length(0)?.u32() << 24) or (dec_length(1)?.u32() << 16) or
        (dec_length(2)?.u32() << 8) or dec_length(3)?.u32()
      else
        return SshDecryptFailed
      end
    if data.size() != (4 + packet_length.usize() + 16) then
      return SshDecryptFailed
    end

    let enc_body = data.trim(4, 4 + packet_length.usize())
    let dec_body = match _chacha20(_main_key, _iv(sequence_number, 1), enc_body)
      | let c: Array[U8] val => c
      | let e: SshCryptoError => return e
      end

    recover val
      let r = Array[U8].create(dec_length.size() + dec_body.size())
      r.append(dec_length)
      r.append(dec_body)
      r
    end

  fun ref decrypt_length(sequence_number: U32, enc_header: Array[U8] val):
    (U32 | SshCryptoError)
  =>
    """
    Decrypt only the 4-byte encrypted packet-length field (K_1, counter 0), so a
    reader can learn how many more bytes to wait for. Unauthenticated by design
    — the tag over the full frame is verified later in decrypt().
    """
    if enc_header.size() < 4 then return SshDecryptFailed end
    let dec = match _chacha20(_header_key, _iv(sequence_number, 0),
      enc_header.trim(0, 4))
      | let c: Array[U8] val => c
      | let e: SshCryptoError => return e
      end
    try
      (dec(0)?.u32() << 24) or (dec(1)?.u32() << 16) or
      (dec(2)?.u32() << 8) or dec(3)?.u32()
    else
      SshDecryptFailed
    end
