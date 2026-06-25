use "../ssh_transport"

primitive SshChannelMsgTypes
  fun channel_open(): U8 => 90
  fun channel_open_confirmation(): U8 => 91
  fun channel_open_failure(): U8 => 92
  fun channel_window_adjust(): U8 => 93
  fun channel_data(): U8 => 94
  fun channel_eof(): U8 => 96
  fun channel_close(): U8 => 97
  fun channel_request(): U8 => 98
  fun channel_success(): U8 => 99
  fun channel_failure(): U8 => 100

primitive SshChannelMessages
  fun channel_open(channel_type: String val, sender_channel: U32,
    initial_window: U32, max_packet_size: U32): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_open())
    w.write_string_from_str(channel_type)
    w.write_u32(sender_channel)
    w.write_u32(initial_window)
    w.write_u32(max_packet_size)
    w.val_bytes()

  fun channel_open_confirmation(recipient_channel: U32, sender_channel: U32,
    initial_window: U32, max_packet_size: U32): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_open_confirmation())
    w.write_u32(recipient_channel)
    w.write_u32(sender_channel)
    w.write_u32(initial_window)
    w.write_u32(max_packet_size)
    w.val_bytes()

  fun channel_open_failure(recipient_channel: U32, reason_code: U32,
    description: String val): Array[U8] val
  =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_open_failure())
    w.write_u32(recipient_channel)
    w.write_u32(reason_code)
    w.write_string_from_str(description)
    w.write_string_from_str("")  // language tag
    w.val_bytes()

  fun channel_window_adjust(recipient_channel: U32, bytes_to_add: U32): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_window_adjust())
    w.write_u32(recipient_channel)
    w.write_u32(bytes_to_add)
    w.val_bytes()

  fun channel_data(recipient_channel: U32, data: Array[U8] val): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_data())
    w.write_u32(recipient_channel)
    w.write_string(data)
    w.val_bytes()

  fun channel_eof(recipient_channel: U32): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_eof())
    w.write_u32(recipient_channel)
    w.val_bytes()

  fun channel_close(recipient_channel: U32): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_close())
    w.write_u32(recipient_channel)
    w.val_bytes()

  fun channel_request_shell(recipient_channel: U32, want_reply: Bool):
    Array[U8] val
  =>
    """Encode a "shell" channel request (RFC 4254 §6.5): start a login shell."""
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_request())
    w.write_u32(recipient_channel)
    w.write_string_from_str("shell")
    w.write_bool(want_reply)
    w.val_bytes()

  fun channel_request_exec(recipient_channel: U32, command: String val,
    want_reply: Bool): Array[U8] val
  =>
    """Encode an "exec" channel request (RFC 4254 §6.5): run a single command."""
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_request())
    w.write_u32(recipient_channel)
    w.write_string_from_str("exec")
    w.write_bool(want_reply)
    w.write_string_from_str(command)
    w.val_bytes()

  fun channel_success(recipient_channel: U32): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_success())
    w.write_u32(recipient_channel)
    w.val_bytes()

  fun channel_failure(recipient_channel: U32): Array[U8] val =>
    let w = SshWireWriter
    w.write_byte(SshChannelMsgTypes.channel_failure())
    w.write_u32(recipient_channel)
    w.val_bytes()
