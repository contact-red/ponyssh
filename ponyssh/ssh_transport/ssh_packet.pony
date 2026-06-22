use "buffered"
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
  // chacha20-poly1305@openssh.com: integrated cipher + MAC keyed by sequence
  var _chacha: (SshChacha20Poly1305Context | None) = None
  // Legacy single-shot context (for tests)
  var _encrypt_ctx: (SshCipherContext | None) = None

  fun ref set_encrypt_ctx(ctx: SshCipherContext, is_aead: Bool = true) =>
    _encrypt_ctx = ctx
    _is_aead = is_aead

  fun ref set_chacha20_poly1305(ctx: SshChacha20Poly1305Context) =>
    """
    Set up chacha20-poly1305@openssh.com encryption. The context carries both
    keys; the packet sequence number is the nonce. There is no separate IV or
    MAC key. Packets align packet_length to an 8-byte boundary.
    """
    _chacha = ctx

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
    _chacha = None

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
    let chacha_active =
      match _chacha
      | let _: SshChacha20Poly1305Context => true
      else false
      end

    let actual_padding = if chacha_active then
      // chacha20-poly1305: the 4-byte length is encrypted separately, so the
      // padded packet_length itself must be a multiple of the 8-byte block.
      let min_pkt_len = 1 + payload.size() + 4
      let rem = min_pkt_len % 8
      if rem == 0 then USize(4) else 4 + (8 - rem) end
    elseif _is_aead then
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

    let pad =
      try
        SshRandom.random_bytes(actual_padding)?
      else
        // CSPRNG failure: emit nothing rather than weak/zero padding. The peer
        // fails to parse the truncated stream and the session tears down.
        return recover iso Array[U8] end
      end

    let result = recover iso
      let w = Writer
      w.u32_be(packet_length)
      w.u8(actual_padding.u8())
      w.write(payload)
      w.write(consume pad)
      let chunks = w.done()
      let buf = Array[U8].create(4 + packet_length.usize())
      for chunk in (consume chunks).values() do
        match chunk
        | let a: Array[U8] val => for b in a.values() do buf.push(b) end
        | let s: String => for b in s.values() do buf.push(b) end
        end
      end
      buf
    end

    _sequence_number = _sequence_number + 1

    // chacha20-poly1305: encrypt the entire framed packet; the nonce is this
    // packet's sequence number (the value before the increment above).
    match _chacha
    | let cc: SshChacha20Poly1305Context =>
      let plaintext: Array[U8] val = consume result
      // On FFI failure, fall back to an empty frame rather than leaking the
      // plaintext packet; the peer then fails to authenticate and tears down.
      let enc: Array[U8] val = match cc.encrypt(_sequence_number - 1, plaintext)
        | let e: Array[U8] val => e
        | let _: SshCryptoError => recover val Array[U8] end
        end
      let out = recover iso Array[U8](enc.size()) end
      out.append(enc)
      return consume out
    end

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
      let pt_r = Reader
      pt_r.append(plaintext)
      try
        let pkt_len_bytes: Array[U8] val = pt_r.block(4)?
        let body: Array[U8] val = pt_r.block(plaintext.size() - 4)?
        let ctx = if key.size() <= 16 then
          SshCipherContext.aes_128_gcm(key, iv, true)?
        else
          SshCipherContext.aes_256_gcm(key, iv, true)?
        end
        try ctx.set_aad(pkt_len_bytes)? end
        let encrypted = match ctx.encrypt(body, true)
          | let e: Array[U8] val => e
          | let _: SshCryptoError => return recover iso Array[U8] end
          end
        let gcm_tag = match ctx.tag_value()
        | let t: Array[U8] val => t
        | None => recover val Array[U8] end
        end
        let out = recover iso Array[U8](4 + encrypted.size() + gcm_tag.size()) end
        out.append(pkt_len_bytes)
        out.append(encrypted)
        out.append(gcm_tag)
        return consume out
      else
        // Cipher setup failed: emit nothing rather than leaking the plaintext
        // packet. The peer fails to parse it and the session tears down.
        return recover iso Array[U8] end
      end
    end

    // Stream cipher (CTR/CBC) with HMAC
    match (_stream_ctx, _mac_key)
    | (let ctx: SshCipherContext, let mkey: Array[U8] val) =>
      let plaintext: Array[U8] val = consume result
      // HMAC(key, sequence_number_BE || unencrypted_packet)
      let mac_w = Writer
      mac_w.u32_be(_sequence_number - 1)  // already incremented
      mac_w.write(plaintext)
      let mac_input = _flatten_writer(consume mac_w)
      let mac = if _use_sha512 then
        SshMac.compute_sha512(mkey, mac_input)
      else
        SshMac.compute_sha256(mkey, mac_input)
      end
      // Encrypt entire packet (including packet_length)
      let encrypted = match ctx.encrypt_stream(plaintext)
        | let e: Array[U8] val => e
        | let _: SshCryptoError => return recover iso Array[U8] end
        end
      let out = recover iso Array[U8](encrypted.size() + _mac_len) end
      out.append(encrypted)
      out.append(mac, 0, _mac_len)
      return consume out
    end

    // Legacy single-shot context (for encrypted packet tests)
    match _encrypt_ctx
    | let ctx: SshCipherContext =>
      if _is_aead then
        let plaintext: Array[U8] val = consume result
        try
          let pt_r = Reader
          pt_r.append(plaintext)
          let pkt_len_bytes: Array[U8] val = pt_r.block(4)?
          let body: Array[U8] val = pt_r.block(plaintext.size() - 4)?
          ctx.set_aad(pkt_len_bytes)?
          let encrypted = match ctx.encrypt(body, true)
            | let e: Array[U8] val => e
            | let _: SshCryptoError => error
            end
          let gcm_tag = match ctx.tag_value()
          | let t: Array[U8] val => t
          | None => recover val Array[U8] end
          end
          let out = recover iso Array[U8](4 + encrypted.size() + gcm_tag.size()) end
          out.append(pkt_len_bytes)
          out.append(encrypted)
          out.append(gcm_tag)
          consume out
        else
          recover iso Array[U8] end
        end
      else
        let plaintext: Array[U8] val = consume result
        let encrypted = match ctx.encrypt(plaintext, false)
          | let e: Array[U8] val => e
          | let _: SshCryptoError => return recover iso Array[U8] end
          end
        let out = recover iso Array[U8](encrypted.size()) end
        out.append(encrypted)
        consume out
      end
    | None =>
      consume result
    end

  fun ref _flatten_writer(w: Writer iso): Array[U8] val =>
    """Collect Writer chunks into a contiguous Array[U8] val."""
    var w' = consume ref w
    let total = w'.size()
    let chunks = w'.done()
    let out = recover iso Array[U8](total) end
    for chunk in (consume chunks).values() do
      match chunk
      | let a: Array[U8] val => out.append(a)
      | let s: String => out.append(s.array())
      end
    end
    consume out

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
  let _buf: Reader = Reader
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
  // chacha20-poly1305@openssh.com: integrated cipher + MAC keyed by sequence
  var _chacha: (SshChacha20Poly1305Context | None) = None
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

  fun ref set_chacha20_poly1305(ctx: SshChacha20Poly1305Context) =>
    """
    Set up chacha20-poly1305@openssh.com decryption. The context carries both
    keys; the packet sequence number is the nonce.
    """
    _chacha = ctx

  fun ref clear_decrypt_ctx() =>
    _decrypt_ctx = None
    _mac_digest_len = 0
    _gcm_key = None
    _gcm_iv = None
    _stream_ctx = None
    _mac_key = None
    _chacha = None
    _decrypted_first_block = None

  fun ref append(data: Array[U8] val) =>
    """Append incoming TCP bytes to the internal buffer."""
    _buf.append(data)

  fun buffered_size(): USize =>
    """Bytes currently buffered but not yet consumed into a packet/line."""
    _buf.size()

  fun ref read(): (Array[U8] val | SshTransportError | None) =>
    """
    Try to read one complete packet from the buffer.
    Returns:
    - payload (Array[U8] val) on success
    - SshTransportError on protocol error
    - None if not enough data yet
    """
    // chacha20-poly1305: decrypt the length header to learn the frame size,
    // then decrypt and authenticate the full packet once it has arrived.
    match _chacha
    | let cc: SshChacha20Poly1305Context =>
      if _buf.size() < 4 then return None end
      let enc_len = try _buf.peek_u32_be()? else return SshPacketCorrupt end
      let enc_header = recover val
        let b = Array[U8].create(4)
        b.push((enc_len >> 24).u8()); b.push((enc_len >> 16).u8())
        b.push((enc_len >> 8).u8()); b.push(enc_len.u8())
        b
      end
      let packet_length = match cc.decrypt_length(_sequence_number, enc_header)
      | let pl: U32 => pl
      | let _: SshCryptoError => return SshPacketCorrupt
      end
      if packet_length.usize() > 35000 then return SshPacketTooLarge end
      let total_needed = 4 + packet_length.usize() + 16
      if _buf.size() < total_needed then return None end
      return try
        let frame: Array[U8] val = _buf.block(total_needed)?
        match cc.decrypt(_sequence_number, frame)
        | let p: Array[U8] val =>
          let payload = _extract_payload_with_header(p)?
          _sequence_number = _sequence_number + 1
          payload
        | let _: SshCryptoError => SshPacketCorrupt
        end
      else
        SshPacketCorrupt
      end
    end

    // Per-packet GCM: create a fresh cipher context with the current IV,
    // then increment the IV's last 8 bytes for the next packet.
    match (_gcm_key, _gcm_iv)
    | (let key: Array[U8] val, let gcm_iv: Array[U8] ref) =>
      let iv_iso = recover iso Array[U8].create(12) end
      for b in gcm_iv.values() do iv_iso.push(b) end
      let iv: Array[U8] val = consume iv_iso
      try
        let ctx = if key.size() <= 16 then
          SshCipherContext.aes_128_gcm(key, iv, false)?
        else
          SshCipherContext.aes_256_gcm(key, iv, false)?
        end
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
    if _buf.size() < 4 then return None end

    let packet_length = try _buf.peek_u32_be()? else return SshPacketCorrupt end
    if packet_length.usize() > 35000 then return SshPacketTooLarge end

    let total_needed = 4 + packet_length.usize() + _mac_digest_len
    if _buf.size() < total_needed then return None end

    try
      let pkt_len_bytes: Array[U8] val = _buf.block(4)?
      let ciphertext: Array[U8] val = _buf.block(packet_length.usize())?
      let gcm_tag: Array[U8] val = _buf.block(_mac_digest_len)?

      ctx.set_aad(pkt_len_bytes)?
      ctx.set_tag(gcm_tag)?

      let decrypted = match ctx.decrypt(ciphertext)
      | let d: Array[U8] val => d
      | let _: SshCryptoError => return SshPacketCorrupt
      end

      let payload = _extract_payload(decrypted)?
      _sequence_number = _sequence_number + 1
      payload
    else
      SshPacketCorrupt
    end

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
      if _buf.size() < _block_size then return None end
      let first_block_enc: Array[U8] val = try _buf.block(_block_size)?
      else return SshPacketCorrupt end
      let first_block = match ctx.decrypt_stream(first_block_enc)
        | let d: Array[U8] val => d
        | let _: SshCryptoError => return SshPacketCorrupt
        end
      // Extract packet_length via buffered.Reader
      let fb_reader = Reader
      fb_reader.append(first_block)
      let pkt_len = try fb_reader.u32_be()? else return SshPacketCorrupt end
      if pkt_len.usize() > 35000 then return SshPacketTooLarge end
      _decrypted_first_block = first_block
      _first_block_packet_length = pkt_len
    end

    // Step 2: Check if we have enough remaining data
    // First block already consumed from _buf
    let pkt_len = _first_block_packet_length
    let total_encrypted = 4 + pkt_len.usize()
    let remaining_encrypted = total_encrypted - _block_size
    if _buf.size() < (remaining_encrypted + _mac_digest_len) then return None end

    let first_block = match _decrypted_first_block
    | let fb: Array[U8] val => fb
    else return SshPacketCorrupt end
    _decrypted_first_block = None

    try
      // Step 3: Decrypt remaining encrypted bytes
      let remaining_dec = if remaining_encrypted > 0 then
        match ctx.decrypt_stream(_buf.block(remaining_encrypted)?)
        | let d: Array[U8] val => d
        | let _: SshCryptoError => error
        end
      else
        recover val Array[U8] end
      end

      // Step 4: Assemble full plaintext packet
      let plaintext = recover iso Array[U8](first_block.size() + remaining_dec.size()) end
      plaintext.append(first_block)
      plaintext.append(remaining_dec)
      let plaintext': Array[U8] val = consume plaintext

      // Step 5: Verify HMAC(key, seq_BE || plaintext_packet)
      let received_mac: Array[U8] val = _buf.block(_mac_digest_len)?

      let mac_w = Writer
      mac_w.u32_be(_sequence_number)
      mac_w.write(plaintext')
      let mac_input': Array[U8] val = _flatten_writer(consume mac_w)

      let expected_mac = if _use_sha512 then
        SshMac.compute_sha512(mkey, mac_input')
      else
        SshMac.compute_sha256(mkey, mac_input')
      end

      if not SshMac.verify(received_mac, expected_mac) then
        return SshPacketCorrupt
      end

      // Step 6: Extract payload from plaintext
      // plaintext is: packet_length(4) || padding_length(1) || payload || padding
      let payload = _extract_payload_with_header(plaintext')?
      _sequence_number = _sequence_number + 1
      payload
    else
      SshPacketCorrupt
    end

  fun ref _read_plaintext(): (Array[U8] val | SshTransportError | None) =>
    """Read an unencrypted packet."""
    if _buf.size() < 4 then return None end

    // Peek at packet_length (big-endian U32)
    let packet_length = try _buf.peek_u32_be()? else return SshPacketCorrupt end

    if packet_length.usize() > 35000 then
      return SshPacketTooLarge
    end

    let total_needed = 4 + packet_length.usize()
    if _buf.size() < total_needed then return None end

    // Now consume
    try
      _buf.skip(4)?  // packet_length field (already peeked)
      let padding_length = _buf.u8()?
      let payload_length = packet_length.usize() - 1 - padding_length.usize()
      if padding_length.usize() < 4 then return SshPacketCorrupt end
      let payload: Array[U8] val = _buf.block(payload_length)?
      _buf.skip(padding_length.usize())?  // discard padding
      _sequence_number = _sequence_number + 1
      payload
    else
      SshPacketCorrupt
    end

  fun _extract_payload(decrypted: Array[U8] val): Array[U8] val ? =>
    """
    Extract payload from decrypted AEAD body: padding_length(1) || payload || padding.
    """
    let r = Reader
    r.append(decrypted)
    let padding_length = r.u8()?.usize()
    if padding_length < 4 then error end
    let payload_length = decrypted.size() - 1 - padding_length
    if (1 + payload_length + padding_length) != decrypted.size() then error end
    r.block(payload_length)?

  fun _extract_payload_with_header(plaintext: Array[U8] val): Array[U8] val ? =>
    """
    Extract payload from full plaintext packet:
    packet_length(4) || padding_length(1) || payload || padding.
    """
    let r = Reader
    r.append(plaintext)
    let pkt_len = r.u32_be()?.usize()
    let padding_length = r.u8()?.usize()
    if padding_length < 4 then error end
    let payload_length = pkt_len - 1 - padding_length
    r.block(payload_length)?

  fun ref read_line(): (String val | None) =>
    """
    Scan the buffer for a line ending in \n. Returns the line content without
    the trailing \r\n (or \n), or None if no complete line yet.
    """
    try
      _buf.line()?
    else
      None
    end

  fun ref _flatten_writer(w: Writer iso): Array[U8] val =>
    """Collect Writer chunks into a contiguous Array[U8] val."""
    var w' = consume ref w
    let total = w'.size()
    let chunks = w'.done()
    let out = recover iso Array[U8](total) end
    for chunk in (consume chunks).values() do
      match chunk
      | let a: Array[U8] val => out.append(a)
      | let s: String => out.append(s.array())
      end
    end
    consume out

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
