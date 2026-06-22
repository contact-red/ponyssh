use "../ssh_crypto"

primitive _TestBytes
  fun apply(size: USize): Array[U8] val =>
    """
    Random bytes for test fixtures. Cryptographic quality is not required here,
    so on the (production-relevant) CSPRNG failure we fall back to a zero-filled
    buffer rather than making every test handle the error. Production code uses
    the partial SshRandom.random_bytes directly and fails closed.
    """
    try
      SshRandom.random_bytes(size)?
    else
      recover val Array[U8].init(0, size) end
    end
