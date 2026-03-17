use "../ssh_error"
use "../ssh_crypto"
use "../ssh_connection"
use "../ssh_auth"

interface SshClientNotify
  be ssh_verify_host_key(session: SshSession tag, host: String val, key: SshHostKey val)
  be ssh_ready(session: SshSession tag)
  be ssh_auth_failed(session: SshSession tag, err: SshAuthError val)
  be ssh_channel_opened(session: SshSession tag, channel_id: U32)
  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val)
  be ssh_channel_error(session: SshSession tag, channel_id: U32, err: SshChannelError val)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32)
  be ssh_error(session: SshSession tag, err: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)

interface SshServerNotify
  be ssh_session_started(session: SshSession tag)
  be ssh_auth_request(session: SshSession tag, request: SshAuthRequest val)
  be ssh_session_ready(session: SshSession tag)
  be ssh_channel_open_request(session: SshSession tag, channel_id: U32, channel_type: String val)
  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  be ssh_channel_data(session: SshSession tag, channel_id: U32, data: Array[U8] val)
  be ssh_channel_error(session: SshSession tag, channel_id: U32, err: SshChannelError val)
  be ssh_channel_closed(session: SshSession tag, channel_id: U32)
  be ssh_error(session: SshSession tag, err: SshTransportError val)
  be ssh_disconnected(session: SshSession tag)
