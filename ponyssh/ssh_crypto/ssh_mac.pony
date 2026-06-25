primitive SshMac
  fun compute_sha256(key: Array[U8] val, data: Array[U8] val): Array[U8] val =>
    _compute(@EVP_sha256(), key, data, 32)

  fun compute_sha512(key: Array[U8] val, data: Array[U8] val): Array[U8] val =>
    _compute(@EVP_sha512(), key, data, 64)

  fun verify(expected: Array[U8] val, computed: Array[U8] val): Bool =>
    """
    Constant-time equality of two MAC/tag byte strings. The loop always visits
    every byte (XOR-accumulate, no early return) so its timing does not reveal
    where a mismatch occurred — do not "optimize" it into an early return, which
    would reintroduce a timing oracle. Used to compare a received MAC against
    the locally computed one.
    """
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

  fun _compute(
    md: Pointer[None] tag,
    key: Array[U8] val,
    data: Array[U8] val,
    digest_size: USize)
    : Array[U8] val
  =>
    let out = recover iso Array[U8].init(0, digest_size) end
    var out_len: U32 = 0
    let rc = @HMAC(md, key.cpointer(), key.size().i32(),
      data.cpointer(), data.size(), out.cpointer(), addressof out_len)
    // HMAC returns NULL on failure. Fail closed: an empty digest never matches
    // a real MAC in verify(), and an empty MAC we emit is rejected by the peer,
    // so an OpenSSL failure tears the session down rather than sending or
    // accepting an unauthenticated packet.
    if rc.is_null() then
      out.truncate(0)
    else
      out.truncate(out_len.usize())
    end
    consume out
