use "buffered"

class ref SshWireWriter
  """Accumulates SSH wire format bytes. Call val_bytes() to get the final val bytes."""
  let _w: Writer ref = Writer

  fun ref write_byte(value: U8) =>
    _w.u8(value)

  fun ref write_bool(value: Bool) =>
    _w.u8(if value then 1 else 0 end)

  fun ref write_u32(value: U32) =>
    _w.u32_be(value)

  fun ref write_string(value: Array[U8] val) =>
    """SSH string: uint32 length followed by data bytes."""
    _w.u32_be(value.size().u32())
    _w.write(value)

  fun ref write_string_from_str(value: String val) =>
    """SSH string from Pony String."""
    _w.u32_be(value.size().u32())
    _w.write(value.array())

  fun ref write_name_list(names: Array[String val] val) =>
    """SSH name-list: comma-separated string."""
    let joined: String val = recover val ",".join(names.values()) end
    write_string_from_str(joined)

  fun ref write_mpint(value: Array[U8] val) =>
    """SSH mpint: uint32 length + big-endian bytes, with leading zero if high bit set."""
    if value.size() == 0 then
      _w.u32_be(0)
    else
      try
        if (value(0)? and 0x80) != 0 then
          _w.u32_be((value.size() + 1).u32())
          _w.u8(0)
        else
          _w.u32_be(value.size().u32())
        end
      end
      _w.write(value)
    end

  fun ref val_bytes(): Array[U8] val =>
    """Collect all chunks into a single contiguous Array[U8] val."""
    let total = _w.size()
    let chunks: Array[ByteSeq] val = _w.done()
    let out = recover iso Array[U8](total) end
    for chunk in chunks.values() do
      match chunk
      | let a: Array[U8] val => out.copy_from(a, 0, out.size(), a.size())
      | let s: String =>
        let sa = s.array()
        out.copy_from(sa, 0, out.size(), sa.size())
      end
    end
    consume out

class SshWireReader
  let _r: Reader ref

  new create(data: Array[U8] val) =>
    _r = Reader
    _r.append(data)

  fun ref read_byte(): U8 ? =>
    _r.u8()?

  fun ref read_bool(): Bool ? =>
    _r.u8()? != 0

  fun ref read_u32(): U32 ? =>
    _r.u32_be()?

  fun ref read_string(): Array[U8] val ? =>
    let len = _r.u32_be()?.usize()
    let block = _r.block(len)?
    consume block

  fun ref read_string_as_str(): String val ? =>
    let bytes = read_string()?
    String.from_array(bytes)

  fun ref read_name_list(): Array[String val] val ? =>
    let s = read_string_as_str()?
    if s.size() == 0 then
      recover val Array[String val] end
    else
      let parts = s.split(",")
      recover val
        let arr = Array[String val](parts.size())
        for p in (consume parts).values() do
          arr.push(consume p)
        end
        arr
      end
    end

  fun ref read_mpint(): Array[U8] val ? =>
    let bytes = read_string()?
    // Strip leading zero byte if present (added to avoid sign-bit confusion)
    if (bytes.size() > 0) and (try bytes(0)? == 0 else false end) then
      recover val
        let arr = Array[U8].create(bytes.size() - 1)
        var i: USize = 1
        while i < bytes.size() do
          arr.push(bytes(i)?)
          i = i + 1
        end
        arr
      end
    else
      bytes
    end

  fun remaining(): USize =>
    _r.size()
