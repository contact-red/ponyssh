use "../ssh_crypto"
use "../ssh_error"

class SshKexStateMachine
  let _role: SshRole

  new create(role: SshRole) =>
    _role = role

  fun ref generate_kexinit(prefs: SshAlgorithmPreferences val): Array[U8] val =>
    """Generate our SSH_MSG_KEXINIT payload with random 16-byte cookie."""
    let cookie = SshRandom.random_bytes(16)
    SshMessages.kexinit(prefs, consume cookie)

  fun ref receive_kexinit(their_payload: Array[U8] val,
    our_prefs: SshAlgorithmPreferences val):
    (SshNegotiatedAlgorithms val | SshTransportError)
  =>
    """Parse their KEXINIT, negotiate algorithms."""
    try
      match SshMessages.decode_kexinit(their_payload)?
      | let their_prefs: SshAlgorithmPreferences val =>
        // Client preferences go first in negotiation per RFC 4253
        match _role
        | SshRoleClient =>
          SshAlgorithmNegotiation.negotiate(our_prefs, their_prefs)
        | SshRoleServer =>
          SshAlgorithmNegotiation.negotiate(their_prefs, our_prefs)
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
    SshDerivedKeys val
  =>
    """
    Derive encryption keys per RFC 4253 section 7.2.

    Each key is: HASH(K || H || X || session_id)
    where K = shared secret (mpint), H = exchange hash, X = single letter.
    """
    let iv_c2s = _derive_key(shared_secret, exchange_hash, 'A', session_id)
    let iv_s2c = _derive_key(shared_secret, exchange_hash, 'B', session_id)
    let enc_key_c2s = _derive_key(shared_secret, exchange_hash, 'C', session_id)
    let enc_key_s2c = _derive_key(shared_secret, exchange_hash, 'D', session_id)
    let mac_key_c2s = _derive_key(shared_secret, exchange_hash, 'E', session_id)
    let mac_key_s2c = _derive_key(shared_secret, exchange_hash, 'F', session_id)

    SshDerivedKeys(iv_c2s, iv_s2c, enc_key_c2s, enc_key_s2c,
      mac_key_c2s, mac_key_s2c)

  fun _derive_key(shared_secret: Array[U8] val, exchange_hash: Array[U8] val,
    letter: U8, session_id: Array[U8] val): Array[U8] val
  =>
    """Compute HASH(K_mpint || H || letter || session_id) using SHA-256."""
    let mpint = _encode_mpint(shared_secret)
    let input = recover val
      let buf = Array[U8]
      for b in mpint.values() do buf.push(b) end
      for b in exchange_hash.values() do buf.push(b) end
      buf.push(letter)
      for b in session_id.values() do buf.push(b) end
      buf
    end
    SshHash.sha256(input)

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
