use "../ssh_error"
use "../ssh_crypto"

class SshPacketWriter
  var _sequence_number: U32 = 0

  fun ref write(payload: Array[U8] val, block_size: USize = 8): Array[U8] iso^ =>
    """
    Frame a payload into an SSH binary packet.
    Returns the complete packet bytes ready for TCP.
    """
    // Calculate padding:
    // packet_length = 1 (padding_length field) + payload.size() + padding
    // total = 4 (packet_length field) + packet_length
    // total must be multiple of block_size
    // padding must be >= 4 and < 256
    let min_packet_len = 1 + payload.size() + 4
    let total = 4 + min_packet_len
    let padding = if (total % block_size) == 0 then
      USize(4)
    else
      4 + (block_size - (total % block_size))
    end
    // Ensure padding < 256
    let actual_padding = if padding >= 256 then padding % block_size else padding end

    let packet_length = (1 + payload.size() + actual_padding).u32()

    let result = recover iso
      let buf = Array[U8].create(4 + packet_length.usize())
      // Write packet_length as big-endian U32
      buf.push((packet_length >> 24).u8())
      buf.push((packet_length >> 16).u8())
      buf.push((packet_length >> 8).u8())
      buf.push(packet_length.u8())
      // Write padding_length
      buf.push(actual_padding.u8())
      // Write payload
      for b in payload.values() do buf.push(b) end
      // Write random padding
      let pad = SshRandom.random_bytes(actual_padding)
      for b in (consume pad).values() do buf.push(b) end
      buf
    end

    _sequence_number = _sequence_number + 1
    consume result

  fun sequence_number(): U32 => _sequence_number

class SshPacketReader
  var _buffer: Array[U8] = Array[U8]
  var _sequence_number: U32 = 0

  fun ref append(data: Array[U8] val) =>
    """Append incoming TCP bytes to the internal buffer."""
    for b in data.values() do _buffer.push(b) end

  fun ref read(): (Array[U8] val | SshTransportError | None) =>
    """
    Try to read one complete packet from the buffer.
    Returns:
    - payload (Array[U8] val) on success
    - SshTransportError on protocol error
    - None if not enough data yet
    """
    // Need at least 4 bytes for packet_length
    if _buffer.size() < 4 then return None end

    // Read packet_length (big-endian U32)
    let packet_length = try
      ((_buffer(0)?.u32() << 24) or
       (_buffer(1)?.u32() << 16) or
       (_buffer(2)?.u32() << 8) or
        _buffer(3)?.u32())
    else
      return SshPacketCorrupt
    end

    // Check max packet size (35000 per RFC 4253 section 6.1)
    if packet_length.usize() > 35000 then
      return SshPacketTooLarge
    end

    let total_needed = 4 + packet_length.usize()
    if _buffer.size() < total_needed then return None end

    // Extract the packet data
    let padding_length = try _buffer(4)? else return SshPacketCorrupt end
    let payload_length = packet_length.usize() - 1 - padding_length.usize()

    // Validate padding
    if padding_length.usize() < 4 then return SshPacketCorrupt end
    if (1 + payload_length + padding_length.usize()) != packet_length.usize() then
      return SshPacketCorrupt
    end

    // Copy buffer contents we need before modifying it
    // Extract payload (bytes 5 through 5+payload_length)
    let p = recover iso Array[U8].create(payload_length) end
    var i: USize = 5
    let end_i = 5 + payload_length
    while i < end_i do
      try p.push(_buffer(i)?) end
      i = i + 1
    end
    let payload: Array[U8] val = consume p

    // Consume the packet from the buffer by rebuilding without consumed bytes
    let new_buffer = Array[U8].create(_buffer.size() - total_needed)
    i = total_needed
    while i < _buffer.size() do
      try new_buffer.push(_buffer(i)?) end
      i = i + 1
    end
    _buffer = new_buffer

    _sequence_number = _sequence_number + 1
    payload

  fun sequence_number(): U32 => _sequence_number
