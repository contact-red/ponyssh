use "../ssh_error"
use "../ssh_crypto"

class SshPacketWriter
  var _sequence_number: U32 = 0
  var _encrypt_ctx: (SshCipherContext | None) = None
  var _is_aead: Bool = false

  fun ref set_encrypt_ctx(ctx: SshCipherContext, is_aead: Bool = true) =>
    _encrypt_ctx = ctx
    _is_aead = is_aead

  fun ref clear_encrypt_ctx() =>
    _encrypt_ctx = None

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

    match _encrypt_ctx
    | let ctx: SshCipherContext =>
      if _is_aead then
        // AEAD (GCM): packet_length in cleartext, encrypt the rest
        // packet_length bytes are AAD
        let plaintext: Array[U8] val = consume result
        let pkt_len_bytes: Array[U8] val = recover val
          let b = Array[U8].create(4)
          try
            b.push(plaintext(0)?)
            b.push(plaintext(1)?)
            b.push(plaintext(2)?)
            b.push(plaintext(3)?)
          end
          b
        end
        let body: Array[U8] val = recover val
          let b = Array[U8].create(plaintext.size() - 4)
          var j: USize = 4
          while j < plaintext.size() do
            try b.push(plaintext(j)?) end
            j = j + 1
          end
          b
        end
        try ctx.set_aad(pkt_len_bytes)? end
        let encrypted = ctx.encrypt(body, true)
        let gcm_tag = match ctx.tag_value()
        | let t: Array[U8] val => t
        | None => recover val Array[U8] end
        end
        recover iso
          let out = Array[U8].create(4 + encrypted.size() + gcm_tag.size())
          for b1 in pkt_len_bytes.values() do out.push(b1) end
          for b2 in encrypted.values() do out.push(b2) end
          for b3 in gcm_tag.values() do out.push(b3) end
          out
        end
      else
        // Non-AEAD: encrypt entire packet
        let plaintext: Array[U8] val = consume result
        let encrypted = ctx.encrypt(plaintext)
        recover iso
          let out = Array[U8].create(encrypted.size())
          for b in encrypted.values() do out.push(b) end
          out
        end
      end
    | None =>
      consume result
    end

  fun sequence_number(): U32 => _sequence_number

class SshPacketReader
  var _buffer: Array[U8] = Array[U8]
  var _sequence_number: U32 = 0
  var _decrypt_ctx: (SshCipherContext | None) = None
  var _mac_digest_len: USize = 0
  var _is_aead: Bool = false

  fun ref set_decrypt_ctx(
    ctx: SshCipherContext,
    mac_digest_len: USize = 16,
    is_aead: Bool = true)
  =>
    _decrypt_ctx = ctx
    _mac_digest_len = mac_digest_len
    _is_aead = is_aead

  fun ref clear_decrypt_ctx() =>
    _decrypt_ctx = None
    _mac_digest_len = 0

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
    match _decrypt_ctx
    | let ctx: SshCipherContext =>
      if _is_aead then
        _read_aead(ctx)
      else
        _read_plaintext()
      end
    | None =>
      _read_plaintext()
    end

  fun ref _read_aead(ctx: SshCipherContext): (Array[U8] val | SshTransportError | None) =>
    """
    Read an AEAD-encrypted packet (GCM).
    Format: packet_length(4, cleartext) || encrypted_body(packet_length) || tag(mac_digest_len)
    """
    // Need at least 4 bytes for packet_length
    if _buffer.size() < 4 then return None end

    // Read packet_length (big-endian U32) — cleartext for AEAD
    let packet_length = try
      ((_buffer(0)?.u32() << 24) or
       (_buffer(1)?.u32() << 16) or
       (_buffer(2)?.u32() << 8) or
        _buffer(3)?.u32())
    else
      return SshPacketCorrupt
    end

    if packet_length.usize() > 35000 then
      return SshPacketTooLarge
    end

    let total_needed = 4 + packet_length.usize() + _mac_digest_len
    if _buffer.size() < total_needed then return None end

    // Extract packet_length bytes (AAD)
    let pkt_len_bytes_iso = recover iso
      let b = Array[U8].create(4)
      b.push((packet_length >> 24).u8())
      b.push((packet_length >> 16).u8())
      b.push((packet_length >> 8).u8())
      b.push(packet_length.u8())
      b
    end
    let pkt_len_bytes: Array[U8] val = consume pkt_len_bytes_iso

    // Extract ciphertext (packet_length bytes after the 4-byte header)
    let ct_buf = recover iso Array[U8].create(packet_length.usize()) end
    var j: USize = 4
    let ct_end = 4 + packet_length.usize()
    while j < ct_end do
      try ct_buf.push(_buffer(j)?) end
      j = j + 1
    end
    let ciphertext: Array[U8] val = consume ct_buf

    // Extract GCM tag (mac_digest_len bytes after ciphertext)
    let tag_buf = recover iso Array[U8].create(_mac_digest_len) end
    j = 4 + packet_length.usize()
    let tag_end = j + _mac_digest_len
    while j < tag_end do
      try tag_buf.push(_buffer(j)?) end
      j = j + 1
    end
    let gcm_tag: Array[U8] val = consume tag_buf

    // Set AAD and GCM tag, then decrypt
    try ctx.set_aad(pkt_len_bytes)? else return SshPacketCorrupt end
    try ctx.set_tag(gcm_tag)? else return SshPacketCorrupt end

    let decrypted = match ctx.decrypt(ciphertext)
    | let d: Array[U8] val => d
    | let _: SshCryptoError => return SshPacketCorrupt
    end

    // Parse decrypted body: padding_length(1) || payload || padding
    if decrypted.size() < 1 then return SshPacketCorrupt end
    let padding_length = try decrypted(0)? else return SshPacketCorrupt end
    let payload_length = decrypted.size() - 1 - padding_length.usize()

    if padding_length.usize() < 4 then return SshPacketCorrupt end
    if (1 + payload_length + padding_length.usize()) != decrypted.size() then
      return SshPacketCorrupt
    end

    let p = recover iso Array[U8].create(payload_length) end
    var i: USize = 1
    let end_i = 1 + payload_length
    while i < end_i do
      try p.push(decrypted(i)?) end
      i = i + 1
    end
    let payload: Array[U8] val = consume p

    // Consume the packet from the buffer
    let new_buffer = Array[U8].create(_buffer.size() - total_needed)
    i = total_needed
    while i < _buffer.size() do
      try new_buffer.push(_buffer(i)?) end
      i = i + 1
    end
    _buffer = new_buffer

    _sequence_number = _sequence_number + 1
    payload

  fun ref _read_plaintext(): (Array[U8] val | SshTransportError | None) =>
    """Read an unencrypted packet."""
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

  fun ref read_line(): (String val | None) =>
    """
    Scan the buffer for a line ending in \n. Returns the line content without
    the trailing \r\n (or \n), or None if no complete line yet.
    """
    var i: USize = 0
    while i < _buffer.size() do
      try
        if _buffer(i)? == '\n' then
          // Found newline. Build the line (excluding \r\n or \n).
          let end_pos = if (i > 0) and (_buffer(i - 1)? == '\r') then
            i - 1
          else
            i
          end
          // Copy line bytes out of buffer first
          let line_bytes = recover iso Array[U8].create(end_pos) end
          var j: USize = 0
          while j < end_pos do
            line_bytes.push(_buffer(j)?)
            j = j + 1
          end
          // Consume the line + newline from the buffer
          let new_buffer = Array[U8].create(_buffer.size() - (i + 1))
          var k: USize = i + 1
          while k < _buffer.size() do
            new_buffer.push(_buffer(k)?)
            k = k + 1
          end
          _buffer = new_buffer
          return String.from_array(consume line_bytes)
        end
      end
      i = i + 1
    end
    None

  fun sequence_number(): U32 => _sequence_number
