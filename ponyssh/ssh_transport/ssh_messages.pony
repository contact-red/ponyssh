primitive SshMsgTypes
  fun disconnect(): U8 => 1
  fun kexinit(): U8 => 20
  fun newkeys(): U8 => 21
  fun kex_ecdh_init(): U8 => 30
  fun kex_ecdh_reply(): U8 => 31

primitive SshDisconnectCodes
  fun host_not_allowed(): U32 => 1
  fun protocol_error(): U32 => 2
  fun key_exchange_failed(): U32 => 3
  fun reserved(): U32 => 4
  fun mac_error(): U32 => 5
  fun compression_error(): U32 => 6
  fun service_not_available(): U32 => 7
  fun protocol_version_not_supported(): U32 => 8
  fun host_key_not_verifiable(): U32 => 9
  fun connection_lost(): U32 => 10
  fun by_application(): U32 => 11
  fun too_many_connections(): U32 => 12
  fun auth_cancelled_by_user(): U32 => 13
  fun no_more_auth_methods(): U32 => 14
  fun illegal_user_name(): U32 => 15

primitive SshMessages
  fun disconnect(reason_code: U32, description: String val): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshMsgTypes.disconnect())
    w.write_u32(reason_code)
    w.write_string_from_str(description)
    w.write_string_from_str("")  // language tag
    w.val_bytes()

  fun kexinit(prefs: SshAlgorithmPreferences val, cookie: Array[U8] val): Array[U8] val =>
    """Encode SSH_MSG_KEXINIT per RFC 4253 section 7.1."""
    let w = SshWireWriter
    w.write_byte(SshMsgTypes.kexinit())
    // 16 bytes cookie
    for b in cookie.values() do w.write_byte(b) end
    // 10 name-lists: kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c,
    //                compression_c2s, compression_s2c, languages_c2s, languages_s2c
    w.write_name_list(prefs.kex)
    w.write_name_list(prefs.host_key)
    w.write_name_list(prefs.cipher_client_to_server)
    w.write_name_list(prefs.cipher_server_to_client)
    w.write_name_list(prefs.mac_client_to_server)
    w.write_name_list(prefs.mac_server_to_client)
    // compression: "none" only
    let none_list: Array[String val] val = recover val [as String val: "none"] end
    w.write_name_list(none_list)
    w.write_name_list(none_list)
    // languages: empty
    let empty_list: Array[String val] val = recover val Array[String val] end
    w.write_name_list(empty_list)
    w.write_name_list(empty_list)
    // first_kex_packet_follows: false
    w.write_bool(false)
    // reserved: 0
    w.write_u32(0)
    w.val_bytes()

  fun decode_kexinit(data: Array[U8] val): (SshAlgorithmPreferences val | None) ? =>
    """Decode SSH_MSG_KEXINIT payload (after the message type byte)."""
    let r = SshWireReader(data)
    let msg_type = r.read_byte()?
    if msg_type != SshMsgTypes.kexinit() then return None end
    // Skip 16-byte cookie
    var i: USize = 0
    while i < 16 do r.read_byte()?; i = i + 1 end
    // Read 10 name-lists
    let kex = r.read_name_list()?
    let host_key = r.read_name_list()?
    let cipher_c2s = r.read_name_list()?
    let cipher_s2c = r.read_name_list()?
    let mac_c2s = r.read_name_list()?
    let mac_s2c = r.read_name_list()?
    r.read_name_list()?  // compression c2s (ignored)
    r.read_name_list()?  // compression s2c (ignored)
    r.read_name_list()?  // languages c2s (ignored)
    r.read_name_list()?  // languages s2c (ignored)
    SshAlgorithmPreferences(kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c)

  fun newkeys(): Array[U8] val =>
    recover val [as U8: SshMsgTypes.newkeys()] end

  fun kex_ecdh_init(client_public: Array[U8] val): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshMsgTypes.kex_ecdh_init())
    w.write_string(client_public)
    w.val_bytes()

  fun kex_ecdh_reply(host_key_blob: Array[U8] val, server_public: Array[U8] val,
    signature: Array[U8] val): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshMsgTypes.kex_ecdh_reply())
    w.write_string(host_key_blob)
    w.write_string(server_public)
    w.write_string(signature)
    w.val_bytes()
