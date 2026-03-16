use "../ssh_error"

class SshKexCurve25519
  """X25519 key exchange using EVP_PKEY with NID_X25519 (1034)."""
  let _pkey: Pointer[None] tag

  new create() ? =>
    let ctx = @EVP_PKEY_CTX_new_id(_NidX25519(), Pointer[None])
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
    let peer_pkey = @EVP_PKEY_new_raw_public_key(_NidX25519(), Pointer[None],
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
    @EVP_PKEY_derive(ctx, Pointer[U8], addressof secret_len)
    let secret = recover iso Array[U8].init(0, secret_len) end
    @EVP_PKEY_derive(ctx, secret.cpointer(), addressof secret_len)
    secret.truncate(secret_len)

    @EVP_PKEY_CTX_free(ctx)
    @EVP_PKEY_free(peer_pkey)
    consume secret

  fun _final() =>
    if not _pkey.is_null() then @EVP_PKEY_free(_pkey) end
