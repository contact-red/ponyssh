use "../ssh_error"

primitive SshRandom
  fun random_bytes(size: USize): Array[U8] iso^ ? =>
    """
    Return `size` cryptographically-random bytes. Errors if the CSPRNG fails
    rather than silently returning a predictable zero-filled buffer.
    """
    let buf = recover iso Array[U8].init(0, size) end
    if @RAND_bytes(buf.cpointer(), size.i32()) != 1 then error end
    consume buf
