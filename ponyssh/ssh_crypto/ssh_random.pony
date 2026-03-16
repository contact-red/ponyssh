use "../ssh_error"

primitive SshRandom
  fun random_bytes(size: USize): Array[U8] iso^ =>
    let buf = recover iso Array[U8].init(0, size) end
    let rc = @RAND_bytes(buf.cpointer(), size.i32())
    ifdef debug then
      if rc != 1 then
        @fprintf[I32](@pony_os_stderr[Pointer[U8]](),
          "RAND_bytes failed\n".cpointer())
      end
    end
    consume buf
