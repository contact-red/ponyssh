primitive SshHash
  fun sha256(data: Array[U8] val): Array[U8] val =>
    """Compute SHA-256 hash of data using OpenSSL EVP_Digest."""
    let ctx = @EVP_MD_CTX_new()
    if ctx.is_null() then return recover val Array[U8] end end
    let rc1 = @EVP_DigestInit_ex(ctx, @EVP_sha256(), Pointer[None])
    if rc1 != 1 then
      @EVP_MD_CTX_free(ctx)
      return recover val Array[U8] end
    end
    let rc2 = @EVP_DigestUpdate(ctx, data.cpointer(), data.size())
    if rc2 != 1 then
      @EVP_MD_CTX_free(ctx)
      return recover val Array[U8] end
    end
    let out = recover iso Array[U8].init(0, 32) end
    var out_len: U32 = 0
    @EVP_DigestFinal_ex(ctx, out.cpointer(), addressof out_len)
    @EVP_MD_CTX_free(ctx)
    out.truncate(out_len.usize())
    consume out
