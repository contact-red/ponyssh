use "../ssh_error"

class val SshAlgorithmPreferences
  let kex: Array[String val] val
  let host_key: Array[String val] val
  let cipher_client_to_server: Array[String val] val
  let cipher_server_to_client: Array[String val] val
  let mac_client_to_server: Array[String val] val
  let mac_server_to_client: Array[String val] val

  new val create(
    kex': Array[String val] val,
    host_key': Array[String val] val,
    cipher_client_to_server': Array[String val] val,
    cipher_server_to_client': Array[String val] val,
    mac_client_to_server': Array[String val] val,
    mac_server_to_client': Array[String val] val)
  =>
    kex = kex'
    host_key = host_key'
    cipher_client_to_server = cipher_client_to_server'
    cipher_server_to_client = cipher_server_to_client'
    mac_client_to_server = mac_client_to_server'
    mac_server_to_client = mac_server_to_client'

class val SshNegotiatedAlgorithms
  let kex: String val
  let host_key: String val
  let cipher_c2s: String val
  let cipher_s2c: String val
  let mac_c2s: String val
  let mac_s2c: String val

  new val create(
    kex': String val, host_key': String val,
    cipher_c2s': String val, cipher_s2c': String val,
    mac_c2s': String val, mac_s2c': String val)
  =>
    kex = kex'; host_key = host_key'
    cipher_c2s = cipher_c2s'; cipher_s2c = cipher_s2c'
    mac_c2s = mac_c2s'; mac_s2c = mac_s2c'

primitive SshAlgorithmNegotiation
  fun negotiate(client: SshAlgorithmPreferences val,
    server: SshAlgorithmPreferences val):
    (SshNegotiatedAlgorithms val | SshAlgorithmNegotiationFailed)
  =>
    """First client preference that server also supports, per category (RFC 4253 §7.1)."""
    let k = _negotiate_one(client.kex, server.kex)
    let hk = _negotiate_one(client.host_key, server.host_key)
    let cc2s = _negotiate_one(client.cipher_client_to_server, server.cipher_client_to_server)
    let cs2c = _negotiate_one(client.cipher_server_to_client, server.cipher_server_to_client)
    let mc2s = _negotiate_one(client.mac_client_to_server, server.mac_client_to_server)
    let ms2c = _negotiate_one(client.mac_server_to_client, server.mac_server_to_client)

    match (k, hk, cc2s, cs2c, mc2s, ms2c)
    | (let k': String val, let hk': String val,
       let cc': String val, let cs': String val,
       let mc': String val, let ms': String val) =>
      SshNegotiatedAlgorithms(k', hk', cc', cs', mc', ms')
    else
      SshAlgorithmNegotiationFailed
    end

  fun _negotiate_one(client_prefs: Array[String val] val,
    server_prefs: Array[String val] val): (String val | None)
  =>
    for c in client_prefs.values() do
      for s in server_prefs.values() do
        if c == s then return c end
      end
    end
    None

primitive SshDefaultAlgorithms
  fun preferences(): SshAlgorithmPreferences val =>
    let kex = recover val
      let a = Array[String val]
      a.push("curve25519-sha256")
      a.push("ecdh-sha2-nistp256")
      a.push("diffie-hellman-group16-sha512")
      a.push("diffie-hellman-group14-sha256")
      a
    end
    let host_key = recover val
      let a = Array[String val]
      a.push("ssh-ed25519")
      a.push("ecdsa-sha2-nistp256")
      a.push("rsa-sha2-512")
      a.push("rsa-sha2-256")
      a
    end
    let cipher = recover val
      let a = Array[String val]
      a.push("chacha20-poly1305@openssh.com")
      a.push("aes256-gcm@openssh.com")
      a.push("aes128-gcm@openssh.com")
      a.push("aes256-ctr")
      a
    end
    let mac = recover val
      let a = Array[String val]
      a.push("hmac-sha2-256")
      a.push("hmac-sha2-512")
      a
    end
    SshAlgorithmPreferences(kex, host_key, cipher, cipher, mac, mac)
