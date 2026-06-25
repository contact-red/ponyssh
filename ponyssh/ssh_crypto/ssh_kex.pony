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
    // Fail closed if extraction fails: an empty key makes the peer's exchange
    // hash disagree and the handshake aborts, rather than sending a zero key.
    if @EVP_PKEY_get_raw_public_key(_pkey, buf.cpointer(), addressof len) != 1
    then
      buf.truncate(0)
    else
      buf.truncate(len)
    end
    consume buf

  fun derive_shared_secret(peer_public: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    // X25519 public keys are exactly 32 bytes. Reject anything else before
    // handing attacker-controlled data to OpenSSL.
    if peer_public.size() != 32 then return SshKeyInvalid end

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

    // First call sizes the secret; second call fills it. A failure here (e.g.
    // a low-order peer point) must abort rather than yield a zero secret.
    var secret_len: USize = 0
    if @EVP_PKEY_derive(ctx, Pointer[U8], addressof secret_len) != 1 then
      @EVP_PKEY_CTX_free(ctx)
      @EVP_PKEY_free(peer_pkey)
      return SshDecryptFailed
    end
    let secret = recover iso Array[U8].init(0, secret_len) end
    let rc = @EVP_PKEY_derive(ctx, secret.cpointer(), addressof secret_len)
    @EVP_PKEY_CTX_free(ctx)
    @EVP_PKEY_free(peer_pkey)
    if rc != 1 then return SshDecryptFailed end
    secret.truncate(secret_len)
    consume secret

  fun _final() =>
    if not _pkey.is_null() then @EVP_PKEY_free(_pkey) end
