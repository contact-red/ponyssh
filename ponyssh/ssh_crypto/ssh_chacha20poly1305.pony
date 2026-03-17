use "../ssh_error"

class SshChacha20Poly1305Context
  """
  chacha20-poly1305@openssh.com cipher context.
  Uses two ChaCha20 keys: main_key (payload) and header_key (packet length).
  Nonce is derived from the packet sequence number.
  """
  let _main_key: Array[U8] val    // 32 bytes
  let _header_key: Array[U8] val  // 32 bytes

  new create(key_material: Array[U8] val) ? =>
    """Key material must be 64 bytes: main_key (0-31) || header_key (32-63)."""
    if key_material.size() != 64 then error end
    _main_key = recover val
      let k = Array[U8].create(32)
      var i: USize = 0
      while i < 32 do k.push(key_material(i)?); i = i + 1 end
      k
    end
    _header_key = recover val
      let k = Array[U8].create(32)
      var i: USize = 32
      while i < 64 do k.push(key_material(i)?); i = i + 1 end
      k
    end

  fun _make_nonce(sequence_number: U32): Array[U8] val =>
    """8-byte nonce: 4 zero bytes + big-endian sequence number."""
    recover val
      let n = Array[U8].init(0, 8)
      try
        n(4)? = (sequence_number >> 24).u8()
        n(5)? = (sequence_number >> 16).u8()
        n(6)? = (sequence_number >> 8).u8()
        n(7)? = sequence_number.u8()
      end
      n
    end

  fun ref encrypt(sequence_number: U32, plaintext_packet: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Encrypt a complete SSH packet (packet_length || padding_length || payload || padding).
    Returns: encrypted_length || encrypted_body || poly1305_tag
    """
    let nonce = _make_nonce(sequence_number)

    if plaintext_packet.size() < 5 then return SshDecryptFailed end

    let pkt_len_bytes = recover val
      let b = Array[U8].create(4)
      try
        b.push(plaintext_packet(0)?)
        b.push(plaintext_packet(1)?)
        b.push(plaintext_packet(2)?)
        b.push(plaintext_packet(3)?)
      end
      b
    end

    let body = recover val
      let b = Array[U8].create(plaintext_packet.size() - 4)
      var i: USize = 4
      while i < plaintext_packet.size() do
        try b.push(plaintext_packet(i)?) end
        i = i + 1
      end
      b
    end

    try
      // Step 1: Encrypt packet_length with header_key (ChaCha20-Poly1305, ignore tag)
      let header_ctx = SshCipherContext.chacha20_poly1305_raw(
        _header_key, nonce, true)?
      let encrypted_header = header_ctx.encrypt(pkt_len_bytes)

      // Step 2: Encrypt body with main_key, using encrypted_header as AAD
      let body_ctx = SshCipherContext.chacha20_poly1305_raw(
        _main_key, nonce, true)?
      body_ctx.set_aad(encrypted_header)?
      let encrypted_body = body_ctx.encrypt(body, true)
      let poly_tag = body_ctx.tag_value()

      // Assemble: encrypted_header || encrypted_body || poly_tag
      let result = recover val
        let r = Array[U8].create(4 + encrypted_body.size() + 16)
        for b in encrypted_header.values() do r.push(b) end
        for b in encrypted_body.values() do r.push(b) end
        match poly_tag
        | let t: Array[U8] val =>
          for b in t.values() do r.push(b) end
        end
        r
      end
      result
    else
      SshDecryptFailed
    end

  fun ref decrypt(sequence_number: U32, data: Array[U8] val):
    (Array[U8] val | SshCryptoError)
  =>
    """
    Decrypt a chacha20-poly1305 packet.
    Input: encrypted_length(4) || encrypted_body(N) || tag(16)
    Returns: packet_length || padding_length || payload || padding
    """
    let nonce = _make_nonce(sequence_number)

    if data.size() < 20 then return SshDecryptFailed end  // 4 + 0 + 16 minimum

    let enc_header = recover val
      let b = Array[U8].create(4)
      try
        b.push(data(0)?); b.push(data(1)?)
        b.push(data(2)?); b.push(data(3)?)
      end
      b
    end

    try
      // Decrypt header to get packet_length
      let header_ctx = SshCipherContext.chacha20_poly1305_raw(
        _header_key, nonce, false)?
      let dec_header_result = header_ctx.decrypt(enc_header)
      let dec_header = match dec_header_result
      | let d: Array[U8] val => d
      | let err: SshCryptoError => return err
      end

      let packet_length = try
        (dec_header(0)?.u32() << 24) or (dec_header(1)?.u32() << 16) or
        (dec_header(2)?.u32() << 8) or dec_header(3)?.u32()
      else
        return SshDecryptFailed
      end

      // Validate size: data must be 4 + packet_length + 16
      if data.size() != (4 + packet_length.usize() + 16) then
        return SshDecryptFailed
      end

      // Extract encrypted body and tag
      let enc_body = recover val
        let b = Array[U8].create(packet_length.usize())
        var i: USize = 4
        let end_i = 4 + packet_length.usize()
        while i < end_i do try b.push(data(i)?) end; i = i + 1 end
        b
      end

      let poly_tag = recover val
        let t = Array[U8].create(16)
        var i: USize = data.size() - 16
        while i < data.size() do try t.push(data(i)?) end; i = i + 1 end
        t
      end

      // Decrypt body with main_key, AAD = encrypted header
      let body_ctx = SshCipherContext.chacha20_poly1305_raw(
        _main_key, nonce, false)?
      body_ctx.set_aad(enc_header)?
      body_ctx.set_tag(poly_tag)?
      let body_result = body_ctx.decrypt(enc_body)
      match body_result
      | let dec_body: Array[U8] val =>
        let result = recover val
          let r = Array[U8].create(4 + dec_body.size())
          for b in dec_header.values() do r.push(b) end
          for b in dec_body.values() do r.push(b) end
          r
        end
        result
      | let err: SshCryptoError => err
      end
    else
      SshDecryptFailed
    end
