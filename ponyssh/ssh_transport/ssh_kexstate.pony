use "../ssh_crypto"
use "../ssh_error"

class SshKexStateMachine
  let _role: SshRole

  new create(role: SshRole) =>
    _role = role

  fun ref generate_kexinit(prefs: SshAlgorithmPreferences val,
    include_strict_marker: Bool = false): Array[U8] val ?
  =>
    """
    Generate our SSH_MSG_KEXINIT payload with a random 16-byte cookie. Errors
    if the CSPRNG fails. When include_strict_marker is set (only the first
    KEXINIT of a connection), the strict-KEX marker for our role is advertised.
    """
    let cookie = SshRandom.random_bytes(16)?
    let marker: (String val | None) =
      if include_strict_marker then SshStrictKex.our_marker(_role) else None end
    SshMessages.kexinit(prefs, consume cookie, marker)

  fun ref receive_kexinit(their_payload: Array[U8] val,
    our_prefs: SshAlgorithmPreferences val):
    (SshNegotiatedAlgorithms val | SshTransportError)
  =>
    """Parse their KEXINIT, negotiate algorithms."""
    try
      match SshMessages.decode_kexinit(their_payload)?
      | let their_prefs: SshAlgorithmPreferences val =>
        // Client preferences go first in negotiation per RFC 4253
        let result = match _role
          | SshRoleClient =>
            SshAlgorithmNegotiation.negotiate(our_prefs, their_prefs)
          | SshRoleServer =>
            SshAlgorithmNegotiation.negotiate(their_prefs, our_prefs)
          end
        // A name common to both peers is only usable if this transport can
        // actually run it. The key-exchange code runs X25519 unconditionally
        // and the cipher code dispatches on exact names, so committing to an
        // unimplemented-but-negotiated algorithm would die mid-handshake (or
        // leave the negotiated name in the exchange hash disagreeing with the
        // math performed). Reject up front instead.
        match result
        | let neg: SshNegotiatedAlgorithms val =>
          if SshSupportedAlgorithms.supports_all(neg) then
            neg
          else
            SshAlgorithmNegotiationFailed
          end
        | SshAlgorithmNegotiationFailed => SshAlgorithmNegotiationFailed
        end
      | None =>
        SshProtocolVersionMismatch
      end
    else
      SshPacketCorrupt
    end

  fun ref derive_keys(shared_secret: Array[U8] val,
    exchange_hash: Array[U8] val, session_id: Array[U8] val,
    negotiated: SshNegotiatedAlgorithms val):
    SshDerivedKeys val ?
  =>
    """
    Derive encryption keys per RFC 4253 section 7.2. Errors if the underlying
    SHA-256 computation fails (rather than producing zero-filled keys).

    Each key is: HASH(K || H || X || session_id)
    where K = shared secret (mpint), H = exchange hash, X = single letter.
    """
    // Encryption keys may need up to 64 bytes (chacha20-poly1305) and MAC
    // keys up to 64 bytes (HMAC-SHA-512); IVs never exceed 16 bytes. Derive
    // a generous length and let each cipher take the prefix it needs.
    let iv_c2s = _derive_key(shared_secret, exchange_hash, 'A', session_id, 32)?
    let iv_s2c = _derive_key(shared_secret, exchange_hash, 'B', session_id, 32)?
    let enc_key_c2s = _derive_key(shared_secret, exchange_hash, 'C', session_id, 64)?
    let enc_key_s2c = _derive_key(shared_secret, exchange_hash, 'D', session_id, 64)?
    let mac_key_c2s = _derive_key(shared_secret, exchange_hash, 'E', session_id, 64)?
    let mac_key_s2c = _derive_key(shared_secret, exchange_hash, 'F', session_id, 64)?

    SshDerivedKeys(iv_c2s, iv_s2c, enc_key_c2s, enc_key_s2c,
      mac_key_c2s, mac_key_s2c)

  fun _derive_key(shared_secret: Array[U8] val, exchange_hash: Array[U8] val,
    letter: U8, session_id: Array[U8] val, output_len: USize): Array[U8] val ?
  =>
    """
    Derive output_len bytes of key material per RFC 4253 section 7.2:

      K1 = HASH(K_mpint || H || letter || session_id)
      K2 = HASH(K_mpint || H || K1)
      Kn = HASH(K_mpint || H || K1 || ... || K(n-1))
      key = (K1 || K2 || ... || Kn) truncated to output_len

    where K = shared secret (as mpint) and H = exchange hash. SHA-256 yields
    32 bytes per round, so keys longer than 32 bytes (chacha20's 64,
    HMAC-SHA-512's 64) require additional rounds. The first 32 bytes are
    identical to a single-round derivation, so shorter keys are unaffected.
    """
    let mpint = _encode_mpint(shared_secret)
    let k1_input = recover val
      let buf = Array[U8]
      buf.append(mpint)
      buf.append(exchange_hash)
      buf.push(letter)
      buf.append(session_id)
      buf
    end
    var material: Array[U8] val = SshHash.sha256(k1_input)?
    while material.size() < output_len do
      let ext_input = recover val
        let buf = Array[U8]
        buf.append(mpint)
        buf.append(exchange_hash)
        buf.append(material)
        buf
      end
      let next = SshHash.sha256(ext_input)?
      material = recover val
        let buf = Array[U8](material.size() + next.size())
        buf.append(material)
        buf.append(next)
        buf
      end
    end
    if material.size() == output_len then
      material
    else
      recover val
        let buf = Array[U8](output_len)
        var i: USize = 0
        while i < output_len do
          try buf.push(material(i)?) end
          i = i + 1
        end
        buf
      end
    end

  fun _encode_mpint(value: Array[U8] val): Array[U8] val =>
    """Encode value as SSH mpint (big-endian with length prefix, leading zero if high bit set)."""
    recover val
      let buf = Array[U8]
      if value.size() == 0 then
        buf.push(0); buf.push(0); buf.push(0); buf.push(0)
      else
        try
          if (value(0)? and 0x80) != 0 then
            let len = (value.size() + 1).u32()
            buf.push((len >> 24).u8()); buf.push((len >> 16).u8())
            buf.push((len >> 8).u8()); buf.push(len.u8())
            buf.push(0)
          else
            let len = value.size().u32()
            buf.push((len >> 24).u8()); buf.push((len >> 16).u8())
            buf.push((len >> 8).u8()); buf.push(len.u8())
          end
        end
        for b in value.values() do buf.push(b) end
      end
      buf
    end

class val SshDerivedKeys
  let iv_c2s: Array[U8] val
  let iv_s2c: Array[U8] val
  let enc_key_c2s: Array[U8] val
  let enc_key_s2c: Array[U8] val
  let mac_key_c2s: Array[U8] val
  let mac_key_s2c: Array[U8] val

  new val create(iv_c2s': Array[U8] val, iv_s2c': Array[U8] val,
    enc_key_c2s': Array[U8] val, enc_key_s2c': Array[U8] val,
    mac_key_c2s': Array[U8] val, mac_key_s2c': Array[U8] val)
  =>
    iv_c2s = iv_c2s'; iv_s2c = iv_s2c'
    enc_key_c2s = enc_key_c2s'; enc_key_s2c = enc_key_s2c'
    mac_key_c2s = mac_key_c2s'; mac_key_s2c = mac_key_s2c'
