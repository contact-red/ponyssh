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
    @HMAC(md, key.cpointer(), key.size().i32(),
      data.cpointer(), data.size(), out.cpointer(), addressof out_len)
    out.truncate(out_len.usize())
    consume out
