use "../ssh_error"

class val SshHostKey
  """Ed25519 public key for host key verification."""
  let algorithm: String val
  let public_key_data: Array[U8] val

  new val create(algorithm': String val, public_key_data': Array[U8] val) =>
    algorithm = algorithm'
    public_key_data = public_key_data'

class SshHostKeyPair
  """
  An Ed25519 key pair loaded from PEM: holds the private key and can sign and
  expose the public key. Despite the name it backs both roles — a server's host
  key and a client's user authentication key — since the underlying operations
  (load, sign, public_key) are identical.
  """
  let algorithm: String val
  let _pkey: Pointer[None] tag

  new create(pem_data: Array[U8] val) ? =>
    """Parse PEM private key via BIO_new_mem_buf + PEM_read_bio_PrivateKey."""
    let bio = @BIO_new_mem_buf(pem_data.cpointer(), pem_data.size().i32())
    if bio.is_null() then error end
    let pkey = @PEM_read_bio_PrivateKey(bio, Pointer[Pointer[None] tag],
      Pointer[None], Pointer[None])
    @BIO_free(bio)
    if pkey.is_null() then error end
    _pkey = pkey
    algorithm = "ssh-ed25519"

  fun sign(data: Array[U8] val): (Array[U8] val | SshCryptoError) =>
    """Sign data using EVP_DigestSign. For Ed25519, the md parameter is null."""
    let md_ctx = @EVP_MD_CTX_new()
    if md_ctx.is_null() then return SshKeyInvalid end

    var pctx: Pointer[None] tag = Pointer[None]
    if @EVP_DigestSignInit(md_ctx, addressof pctx, Pointer[None],
      Pointer[None], _pkey) != 1
    then
      @EVP_MD_CTX_free(md_ctx)
      return SshKeyInvalid
    end

    // First call: get required signature length
    var sig_len: USize = 0
    if @EVP_DigestSign(md_ctx, Pointer[U8], addressof sig_len,
      data.cpointer(), data.size()) != 1
    then
      @EVP_MD_CTX_free(md_ctx)
      return SshSignatureInvalid
    end

    // Second call: perform signing
    let sig = recover iso Array[U8].init(0, sig_len) end
    let rc = @EVP_DigestSign(md_ctx, sig.cpointer(), addressof sig_len,
      data.cpointer(), data.size())
    @EVP_MD_CTX_free(md_ctx)

    if rc != 1 then return SshSignatureInvalid end
    sig.truncate(sig_len)
    consume sig

  fun public_key(): SshHostKey =>
    """Extract the public key as an SshHostKey."""
    let buf = recover iso Array[U8].init(0, 32) end
    var len: USize = 32
    // Fail closed on extraction failure: an empty key fails signature
    // verification downstream rather than yielding a zero key.
    if @EVP_PKEY_get_raw_public_key(_pkey, buf.cpointer(), addressof len) != 1
    then
      buf.truncate(0)
    else
      buf.truncate(len)
    end
    SshHostKey(algorithm, consume buf)

  fun _final() =>
    if not _pkey.is_null() then @EVP_PKEY_free(_pkey) end

primitive SshHostKeyVerify
  """Verifies Ed25519 signatures against an SshHostKey."""
  fun verify(key: SshHostKey val, signature: Array[U8] val,
    data: Array[U8] val): (Bool | SshCryptoError)
  =>
    // Only ssh-ed25519 host keys are supported. Reject any other algorithm
    // explicitly rather than relying on OpenSSL's raw-key length check to fail
    // closed for us.
    if key.algorithm != "ssh-ed25519" then return SshKeyInvalid end
    let pkey = @EVP_PKEY_new_raw_public_key(_NidEd25519(), Pointer[None],
      key.public_key_data.cpointer(), key.public_key_data.size())
    if pkey.is_null() then return SshKeyInvalid end

    let md_ctx = @EVP_MD_CTX_new()
    if md_ctx.is_null() then
      @EVP_PKEY_free(pkey)
      return SshKeyInvalid
    end

    var pctx: Pointer[None] tag = Pointer[None]
    if @EVP_DigestVerifyInit(md_ctx, addressof pctx, Pointer[None],
      Pointer[None], pkey) != 1
    then
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
