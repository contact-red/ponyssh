primitive SshHash
  fun sha256(data: Array[U8] val): Array[U8] val ? =>
    """
    Compute SHA-256 of data using OpenSSL EVP_Digest. Errors on any OpenSSL
    failure rather than returning an empty hash — a silently-empty hash would
    become an empty session id and zero-derived keys.
    """
    let ctx = @EVP_MD_CTX_new()
    if ctx.is_null() then error end
    if @EVP_DigestInit_ex(ctx, @EVP_sha256(), Pointer[None]) != 1 then
      @EVP_MD_CTX_free(ctx)
      error
    end
    if @EVP_DigestUpdate(ctx, data.cpointer(), data.size()) != 1 then
      @EVP_MD_CTX_free(ctx)
      error
    end
    let out = recover iso Array[U8].init(0, 32) end
    var out_len: U32 = 0
    let rc = @EVP_DigestFinal_ex(ctx, out.cpointer(), addressof out_len)
    @EVP_MD_CTX_free(ctx)
    if rc != 1 then error end
    out.truncate(out_len.usize())
    consume out
