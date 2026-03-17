class ref SshWireWriter
  """Accumulates SSH wire format bytes. Call val_bytes() to get the final val bytes."""
  var _buf: Array[U8] trn

  new create() =>
    _buf = recover trn Array[U8] end

  fun ref write_byte(value: U8) =>
    _buf.push(value)

  fun ref write_bool(value: Bool) =>
    _buf.push(if value then 1 else 0 end)

  fun ref write_u32(value: U32) =>
    _buf.push((value >> 24).u8())
    _buf.push((value >> 16).u8())
    _buf.push((value >> 8).u8())
    _buf.push(value.u8())

  fun ref write_string(value: Array[U8] val) =>
    """SSH string: uint32 length followed by data bytes."""
    write_u32(value.size().u32())
    for b in value.values() do _buf.push(b) end

  fun ref write_string_from_str(value: String val) =>
    """SSH string from Pony String."""
    write_u32(value.size().u32())
    for b in value.values() do _buf.push(b) end

  fun ref write_name_list(names: Array[String val] val) =>
    """SSH name-list: comma-separated string."""
    let joined: String val = recover val ",".join(names.values()) end
    write_string_from_str(joined)

  fun ref write_mpint(value: Array[U8] val) =>
    """SSH mpint: uint32 length + big-endian bytes, with leading zero if high bit set."""
    if value.size() == 0 then
      write_u32(0)
    else
      try
        if (value(0)? and 0x80) != 0 then
          // Need leading zero byte
          write_u32((value.size() + 1).u32())
          _buf.push(0)
        else
          write_u32(value.size().u32())
        end
      end
      for b in value.values() do _buf.push(b) end
    end

  fun ref val_bytes(): Array[U8] val =>
    """Freeze accumulated bytes into a sendable val array."""
    let b: Array[U8] val = _buf = recover trn Array[U8] end
    b

class SshWireReader
  let _data: Array[U8] val
  var _offset: USize = 0

  new create(data: Array[U8] val) =>
    _data = data

  fun ref read_byte(): U8 ? =>
    let v = _data(_offset)?
    _offset = _offset + 1
    v

  fun ref read_bool(): Bool ? =>
    read_byte()? != 0

  fun ref read_u32(): U32 ? =>
    let b0 = _data(_offset)?.u32()
    let b1 = _data(_offset + 1)?.u32()
    let b2 = _data(_offset + 2)?.u32()
    let b3 = _data(_offset + 3)?.u32()
    _offset = _offset + 4
    (b0 << 24) or (b1 << 16) or (b2 << 8) or b3

  fun ref read_string(): Array[U8] val ? =>
    let len = read_u32()?.usize()
    let result = recover val
      let arr = Array[U8].create(len)
      var i: USize = 0
      while i < len do
        arr.push(_data(_offset + i)?)
        i = i + 1
      end
      arr
    end
    _offset = _offset + len
    result

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
        let arr = Array[String val].create(parts.size())
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
    if _offset > _data.size() then 0 else _data.size() - _offset end
