use "../ssh_error"

class ref SshCipherContext
  var _ctx: Pointer[None] tag
  let _encrypting: Bool
  var _tag: (Array[U8] val | None)

  new ref aes_256_gcm(
    key: Array[U8] val,
    iv: Array[U8] val,
    encrypting: Bool)
    ?
  =>
    _encrypting = encrypting
    _tag = None
    let ctx = @EVP_CIPHER_CTX_new()
    if ctx.is_null() then error end
    _ctx = ctx
    let cipher = @EVP_aes_256_gcm()
    let rc = if encrypting then
      @EVP_EncryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    else
      @EVP_DecryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    end
    if rc != 1 then
      @EVP_CIPHER_CTX_free(ctx)
      _ctx = Pointer[None]
      error
    end

  new ref aes_128_gcm(
    key: Array[U8] val,
    iv: Array[U8] val,
    encrypting: Bool)
    ?
  =>
    _encrypting = encrypting
    _tag = None
    let ctx = @EVP_CIPHER_CTX_new()
    if ctx.is_null() then error end
    _ctx = ctx
    let cipher = @EVP_aes_128_gcm()
    let rc = if encrypting then
      @EVP_EncryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    else
      @EVP_DecryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    end
    if rc != 1 then
      @EVP_CIPHER_CTX_free(ctx)
      _ctx = Pointer[None]
      error
    end

  new ref aes_256_ctr(
    key: Array[U8] val,
    iv: Array[U8] val,
    encrypting: Bool)
    ?
  =>
    _encrypting = encrypting
    _tag = None
    let ctx = @EVP_CIPHER_CTX_new()
    if ctx.is_null() then error end
    _ctx = ctx
    let cipher = @EVP_aes_256_ctr()
    let rc = if encrypting then
      @EVP_EncryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    else
      @EVP_DecryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    end
    if rc != 1 then
      @EVP_CIPHER_CTX_free(ctx)
      _ctx = Pointer[None]
      error
    end

  new ref aes_128_cbc(
    key: Array[U8] val,
    iv: Array[U8] val,
    encrypting: Bool)
    ?
  =>
    _encrypting = encrypting
    _tag = None
    let ctx = @EVP_CIPHER_CTX_new()
    if ctx.is_null() then error end
    _ctx = ctx
    let cipher = @EVP_aes_128_cbc()
    let rc = if encrypting then
      @EVP_EncryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    else
      @EVP_DecryptInit_ex(ctx, cipher, Pointer[None], key.cpointer(), iv.cpointer())
    end
    if rc != 1 then
      @EVP_CIPHER_CTX_free(ctx)
      _ctx = Pointer[None]
      error
    end
    @EVP_CIPHER_CTX_set_padding(ctx, 0)

  fun ref set_aad(aad: Array[U8] val) ? =>
    """
    Set additional authenticated data for AEAD ciphers (GCM).
    Must be called before encrypt/decrypt.
    """
    var aad_len: I32 = 0
    let rc = if _encrypting then
      @EVP_EncryptUpdate(
        _ctx,
        Pointer[U8],
        addressof aad_len,
        aad.cpointer(),
        aad.size().i32())
    else
      @EVP_DecryptUpdate(
        _ctx,
        Pointer[U8],
        addressof aad_len,
        aad.cpointer(),
        aad.size().i32())
    end
    if rc != 1 then error end

  fun ref encrypt(plaintext: Array[U8] val, is_aead: Bool = true):
    (Array[U8] val | SshCryptoError)
  =>
    let out_size = plaintext.size() + 16
    let out = recover iso Array[U8].init(0, out_size) end
    var out_len: I32 = 0
    if @EVP_EncryptUpdate(_ctx, out.cpointer(), addressof out_len,
      plaintext.cpointer(), plaintext.size().i32()) != 1
    then
      return SshEncryptFailed
    end
    var final_len: I32 = 0
    if @EVP_EncryptFinal_ex(_ctx, out.cpointer(out_len.usize()),
      addressof final_len) != 1
    then
      return SshEncryptFailed
    end
    let total = (out_len + final_len).usize()
    out.truncate(total)
    if is_aead then
      let tag_buf = recover iso Array[U8].init(0, 16) end
      if @EVP_CIPHER_CTX_ctrl(_ctx, _EvpCtrlGcmGetTag(), 16,
        tag_buf.cpointer()) != 1
      then
        return SshEncryptFailed
      end
      _tag = consume tag_buf
    end
    consume out

  fun ref set_tag(gcm_tag: Array[U8] val) ? =>
    let rc = @EVP_CIPHER_CTX_ctrl(
      _ctx,
      _EvpCtrlGcmSetTag(),
      gcm_tag.size().i32(),
      gcm_tag.cpointer())
    if rc != 1 then error end

  fun box tag_value(): (Array[U8] val | None) =>
    _tag

  fun ref decrypt(ciphertext: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    let out_size = ciphertext.size() + 16
    let out = recover iso Array[U8].init(0, out_size) end
    var out_len: I32 = 0
    @EVP_DecryptUpdate(
      _ctx,
      out.cpointer(),
      addressof out_len,
      ciphertext.cpointer(),
      ciphertext.size().i32())
    var final_len: I32 = 0
    let rc = @EVP_DecryptFinal_ex(
      _ctx,
      out.cpointer(out_len.usize()),
      addressof final_len)
    if rc != 1 then
      return SshDecryptFailed
    end
    let total = (out_len + final_len).usize()
    out.truncate(total)
    consume out

  fun ref encrypt_stream(plaintext: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Streaming encrypt (Update only, no Final). For CTR/CBC where the cipher
    context persists across packets.
    """
    let out = recover iso Array[U8].init(0, plaintext.size() + 16) end
    var out_len: I32 = 0
    if @EVP_EncryptUpdate(_ctx, out.cpointer(), addressof out_len,
      plaintext.cpointer(), plaintext.size().i32()) != 1
    then
      return SshEncryptFailed
    end
    out.truncate(out_len.usize())
    consume out

  fun ref decrypt_stream(ciphertext: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Streaming decrypt (Update only, no Final). For CTR/CBC where the cipher
    context persists across packets.
    """
    let out = recover iso Array[U8].init(0, ciphertext.size() + 16) end
    var out_len: I32 = 0
    if @EVP_DecryptUpdate(_ctx, out.cpointer(), addressof out_len,
      ciphertext.cpointer(), ciphertext.size().i32()) != 1
    then
      return SshDecryptFailed
    end
    out.truncate(out_len.usize())
    consume out

  fun _final() =>
    if not _ctx.is_null() then
      @EVP_CIPHER_CTX_free(_ctx)
    end
