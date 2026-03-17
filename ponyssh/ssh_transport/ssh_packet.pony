use "../ssh_error"
use "../ssh_crypto"

class SshPacketWriter
  var _sequence_number: U32 = 0
  var _is_aead: Bool = false
  // Per-packet GCM: key + 12-byte IV (last 8 bytes incremented per packet)
  var _gcm_key: (Array[U8] val | None) = None
  var _gcm_iv: (Array[U8] ref | None) = None
  // Stream cipher (CTR/CBC): persistent context + MAC key
  var _stream_ctx: (SshCipherContext | None) = None
  var _mac_key: (Array[U8] val | None) = None
  var _mac_len: USize = 0
  var _use_sha512: Bool = false
  // Legacy single-shot context (for tests)
  var _encrypt_ctx: (SshCipherContext | None) = None

  fun ref set_encrypt_ctx(ctx: SshCipherContext, is_aead: Bool = true) =>
    _encrypt_ctx = ctx
    _is_aead = is_aead

  fun ref set_gcm_params(key: Array[U8] val, iv: Array[U8] val) =>
    """
    Set up per-packet GCM encryption. A fresh cipher context is created per
    packet. iv must be 12 bytes. The last 8 bytes are incremented per packet.
    """
    _gcm_key = key
    let iv_copy = Array[U8].create(12)
    for b in iv.values() do iv_copy.push(b) end
    _gcm_iv = iv_copy
    _is_aead = true

  fun ref set_stream_cipher(ctx: SshCipherContext, mac_key: Array[U8] val,
    mac_len: USize, use_sha512: Bool = false)
  =>
    """
    Set up streaming encryption (CTR/CBC) with HMAC. The cipher context
    persists across packets. MAC is HMAC-SHA256 or HMAC-SHA512.
    """
    _stream_ctx = ctx
    _mac_key = mac_key
    _mac_len = mac_len
    _use_sha512 = use_sha512
    _is_aead = false

  fun ref clear_encrypt_ctx() =>
    _encrypt_ctx = None
    _gcm_key = None
    _gcm_iv = None
    _stream_ctx = None
    _mac_key = None

  fun ref write(payload: Array[U8] val, block_size: USize = 8): Array[U8] iso^ =>
    """
    Frame a payload into an SSH binary packet.
    Returns the complete packet bytes ready for TCP.
    """
    // Calculate padding:
    // packet_length = 1 (padding_length field) + payload.size() + padding
    // padding must be >= 4 and < 256
    //
    // Alignment depends on cipher mode:
    // - Plaintext / non-AEAD: (4 + packet_length) must be multiple of block_size
    //   because the packet_length field is encrypted along with the body
    // - AEAD (GCM): packet_length itself must be multiple of block_size
    //   because the 4-byte length is plaintext AAD, not part of the encrypted block
    let actual_padding = if _is_aead then
      // AEAD: align packet_length to block_size
      let min_pkt_len = 1 + payload.size() + 4  // with minimum 4 padding
      let rem = min_pkt_len % block_size
      if rem == 0 then USize(4) else 4 + (block_size - rem) end
    else
      // Plaintext / non-AEAD: align (4 + packet_length) to block_size
      let min_pkt_len = 1 + payload.size() + 4
      let total = 4 + min_pkt_len
      let rem = total % block_size
      if rem == 0 then USize(4) else 4 + (block_size - rem) end
    end

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

    // Per-packet GCM: create a fresh cipher context with the current IV,
    // then increment the IV's last 8 bytes for the next packet.
    // This matches OpenSSH's EVP_CTRL_GCM_IV_GEN behavior.
    match (_gcm_key, _gcm_iv)
    | (let key: Array[U8] val, let gcm_iv: Array[U8] ref) =>
      let plaintext: Array[U8] val = consume result
      // Snapshot the current IV as iso then consume to val
      let iv_iso = recover iso Array[U8].create(12) end
      for b in gcm_iv.values() do iv_iso.push(b) end
      let iv: Array[U8] val = consume iv_iso
      // Increment the last 8 bytes of the mutable IV for the next packet
      _increment_iv(gcm_iv)
      let pkt_len_bytes: Array[U8] val = recover val
        let b = Array[U8].create(4)
        try
          b.push(plaintext(0)?); b.push(plaintext(1)?)
          b.push(plaintext(2)?); b.push(plaintext(3)?)
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
      try
        let ctx = SshCipherContext.aes_256_gcm(key, iv, true)?
        try ctx.set_aad(pkt_len_bytes)? end
        let encrypted = ctx.encrypt(body, true)
        let gcm_tag = match ctx.tag_value()
        | let t: Array[U8] val => t
        | None => recover val Array[U8] end
        end
        return recover iso
          let out = Array[U8].create(4 + encrypted.size() + gcm_tag.size())
          for b1 in pkt_len_bytes.values() do out.push(b1) end
          for b2 in encrypted.values() do out.push(b2) end
          for b3 in gcm_tag.values() do out.push(b3) end
          out
        end
      else
        // Cipher creation failed, return plaintext (should not happen)
        return recover iso
          let out = Array[U8].create(plaintext.size())
          for b in plaintext.values() do out.push(b) end
          out
        end
      end
    end

    // Stream cipher (CTR/CBC) with HMAC
    match (_stream_ctx, _mac_key)
    | (let ctx: SshCipherContext, let mkey: Array[U8] val) =>
      let plaintext: Array[U8] val = consume result
      // HMAC(key, sequence_number_BE || unencrypted_packet)
      let seq = _sequence_number - 1  // already incremented
      let mac_input_iso = recover iso Array[U8].create(4 + plaintext.size()) end
      mac_input_iso.push((seq >> 24).u8())
      mac_input_iso.push((seq >> 16).u8())
      mac_input_iso.push((seq >> 8).u8())
      mac_input_iso.push(seq.u8())
      for b in plaintext.values() do mac_input_iso.push(b) end
      let mac_input: Array[U8] val = consume mac_input_iso
      let mac = if _use_sha512 then
        SshMac.compute_sha512(mkey, mac_input)
      else
        SshMac.compute_sha256(mkey, mac_input)
      end
      // Encrypt entire packet (including packet_length)
      let encrypted = ctx.encrypt_stream(plaintext)
      return recover iso
        let out = Array[U8].create(encrypted.size() + _mac_len)
        for b in encrypted.values() do out.push(b) end
        var i: USize = 0
        while i < _mac_len do
          try out.push(mac(i)?) end
          i = i + 1
        end
        out
      end
    end

    // Legacy single-shot context (for encrypted packet tests)
    match _encrypt_ctx
    | let ctx: SshCipherContext =>
      if _is_aead then
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

  fun ref _increment_iv(iv: Array[U8] ref) =>
    """Increment the last 8 bytes of a 12-byte IV as a big-endian counter."""
    try
      var i: USize = iv.size() - 1
      while i >= 4 do
        let v = iv(i)? + 1
        iv(i)? = v
        if v != 0 then return end  // no carry
        i = i - 1
      end
    end

  fun sequence_number(): U32 => _sequence_number

class SshPacketReader
  var _buffer: Array[U8] = Array[U8]
  var _sequence_number: U32 = 0
  var _is_aead: Bool = false
  // Per-packet GCM state
  var _gcm_key: (Array[U8] val | None) = None
  var _gcm_iv: (Array[U8] ref | None) = None
  var _mac_digest_len: USize = 0
  // Stream cipher (CTR/CBC)
  var _stream_ctx: (SshCipherContext | None) = None
  var _mac_key: (Array[U8] val | None) = None
  var _use_sha512: Bool = false
  var _block_size: USize = 16
  // Decrypted first block (waiting for rest of packet)
  var _decrypted_first_block: (Array[U8] val | None) = None
  var _first_block_packet_length: U32 = 0
  // Legacy single-shot context
  var _decrypt_ctx: (SshCipherContext | None) = None

  fun ref set_decrypt_ctx(
    ctx: SshCipherContext,
    mac_digest_len: USize = 16,
    is_aead: Bool = true)
  =>
    _decrypt_ctx = ctx
    _mac_digest_len = mac_digest_len
    _is_aead = is_aead

  fun ref set_gcm_params(key: Array[U8] val, iv: Array[U8] val) =>
    """
    Set up per-packet GCM decryption. A fresh cipher context is created per
    packet. iv must be 12 bytes. The last 8 bytes are incremented per packet.
    """
    _gcm_key = key
    let iv_copy = Array[U8].create(12)
    for b in iv.values() do iv_copy.push(b) end
    _gcm_iv = iv_copy
    _mac_digest_len = 16
    _is_aead = true

  fun ref set_stream_cipher(ctx: SshCipherContext, mac_key: Array[U8] val,
    mac_len: USize, block_size: USize = 16, use_sha512: Bool = false)
  =>
    """
    Set up streaming decryption (CTR/CBC) with HMAC verification.
    """
    _stream_ctx = ctx
    _mac_key = mac_key
    _mac_digest_len = mac_len
    _block_size = block_size
    _use_sha512 = use_sha512
    _is_aead = false

  fun ref clear_decrypt_ctx() =>
    _decrypt_ctx = None
    _mac_digest_len = 0
    _gcm_key = None
    _gcm_iv = None
    _stream_ctx = None
    _mac_key = None
    _decrypted_first_block = None

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
    // Per-packet GCM: create a fresh cipher context with the current IV,
    // then increment the IV's last 8 bytes for the next packet.
    match (_gcm_key, _gcm_iv)
    | (let key: Array[U8] val, let gcm_iv: Array[U8] ref) =>
      let iv_iso = recover iso Array[U8].create(12) end
      for b in gcm_iv.values() do iv_iso.push(b) end
      let iv: Array[U8] val = consume iv_iso
      try
        let ctx = SshCipherContext.aes_256_gcm(key, iv, false)?
        let result = _read_aead(ctx)
        match result
        | let _: Array[U8] val => _increment_iv(gcm_iv)
        end
        return result
      else
        return SshPacketCorrupt
      end
    end

    // Stream cipher (CTR/CBC) with HMAC
    match (_stream_ctx, _mac_key)
    | (let ctx: SshCipherContext, let mkey: Array[U8] val) =>
      return _read_stream(ctx, mkey)
    end

    // Legacy single-shot context (for tests)
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

  fun ref _read_stream(ctx: SshCipherContext, mkey: Array[U8] val):
    (Array[U8] val | SshTransportError | None)
  =>
    """
    Read a stream-cipher encrypted packet (CTR/CBC) with HMAC.
    Decrypt first block to get packet_length, then decrypt the rest,
    then verify HMAC.
    """
    // Step 1: If we haven't decrypted the first block yet, do it now
    match _decrypted_first_block
    | None =>
      // Need at least one cipher block
      if _buffer.size() < _block_size then return None end
      // Extract and decrypt first block
      let first_block_enc = recover iso Array[U8].create(_block_size) end
      var i: USize = 0
      while i < _block_size do
        try first_block_enc.push(_buffer(i)?) end
        i = i + 1
      end
      let first_block = ctx.decrypt_stream(consume first_block_enc)
      // Extract packet_length from first 4 bytes
      let pkt_len = try
        (first_block(0)?.u32() << 24) or (first_block(1)?.u32() << 16) or
        (first_block(2)?.u32() << 8) or first_block(3)?.u32()
      else
        return SshPacketCorrupt
      end
      if pkt_len.usize() > 35000 then return SshPacketTooLarge end
      _decrypted_first_block = first_block
      _first_block_packet_length = pkt_len
    end

    // Step 2: Check if we have enough data for the full packet + MAC
    let pkt_len = _first_block_packet_length
    let total_encrypted = 4 + pkt_len.usize()  // packet_length field + body
    let total_needed = total_encrypted + _mac_digest_len
    if _buffer.size() < total_needed then return None end

    // Step 3: Decrypt remaining encrypted bytes (after first block)
    let first_block = match _decrypted_first_block
    | let fb: Array[U8] val => fb
    else
      return SshPacketCorrupt  // shouldn't happen
    end
    _decrypted_first_block = None

    let remaining_enc_size = total_encrypted - _block_size
    let remaining_dec = if remaining_enc_size > 0 then
      let enc_rest = recover iso Array[U8].create(remaining_enc_size) end
      var j: USize = _block_size
      while j < total_encrypted do
        try enc_rest.push(_buffer(j)?) end
        j = j + 1
      end
      ctx.decrypt_stream(consume enc_rest)
    else
      recover val Array[U8] end
    end

    // Step 4: Assemble full plaintext packet
    let plaintext_iso = recover iso
      Array[U8].create(first_block.size() + remaining_dec.size())
    end
    for b in first_block.values() do plaintext_iso.push(b) end
    for b in remaining_dec.values() do plaintext_iso.push(b) end
    let plaintext: Array[U8] val = consume plaintext_iso

    // Step 5: Extract and verify HMAC
    let received_mac_iso = recover iso Array[U8].create(_mac_digest_len) end
    var k: USize = total_encrypted
    while k < total_needed do
      try received_mac_iso.push(_buffer(k)?) end
      k = k + 1
    end
    let received_mac: Array[U8] val = consume received_mac_iso

    // Compute expected MAC: HMAC(key, seq_number_BE || plaintext_packet)
    let mac_input_iso = recover iso Array[U8].create(4 + plaintext.size()) end
    let seq = _sequence_number
    mac_input_iso.push((seq >> 24).u8())
    mac_input_iso.push((seq >> 16).u8())
    mac_input_iso.push((seq >> 8).u8())
    mac_input_iso.push(seq.u8())
    for b in plaintext.values() do mac_input_iso.push(b) end
    let mac_input: Array[U8] val = consume mac_input_iso

    let expected_mac = if _use_sha512 then
      SshMac.compute_sha512(mkey, mac_input)
    else
      SshMac.compute_sha256(mkey, mac_input)
    end

    if not SshMac.verify(received_mac, expected_mac) then
      return SshPacketCorrupt
    end

    // Step 6: Parse plaintext — packet_length(4) || padding_length(1) || payload || padding
    let padding_length = try plaintext(4)? else return SshPacketCorrupt end
    let payload_length = pkt_len.usize() - 1 - padding_length.usize()
    if padding_length.usize() < 4 then return SshPacketCorrupt end

    let p = recover iso Array[U8].create(payload_length) end
    var m: USize = 5
    let end_m = 5 + payload_length
    while m < end_m do
      try p.push(plaintext(m)?) end
      m = m + 1
    end
    let payload: Array[U8] val = consume p

    // Consume from buffer
    let new_buffer = Array[U8].create(_buffer.size() - total_needed)
    var n: USize = total_needed
    while n < _buffer.size() do
      try new_buffer.push(_buffer(n)?) end
      n = n + 1
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

  fun ref _increment_iv(iv: Array[U8] ref) =>
    """Increment the last 8 bytes of a 12-byte IV as a big-endian counter."""
    try
      var i: USize = iv.size() - 1
      while i >= 4 do
        let v = iv(i)? + 1
        iv(i)? = v
        if v != 0 then return end
        i = i - 1
      end
    end

  fun sequence_number(): U32 => _sequence_number
