use "../ssh_error"
use "../ssh_crypto"

type SshSessionState is
  ( SshStateHandshake
  | SshStateKeyExchange
  | SshStateAuth
  | SshStateConnected
  | SshStateDisconnected )

class SshStateHandshake
  """Waiting for version exchange."""
  var remote_version: (String val | None) = None

class SshStateKeyExchange
  """Key exchange in progress."""
  let our_kexinit: Array[U8] val
  let their_kexinit: Array[U8] val
  let negotiated: SshNegotiatedAlgorithms val
  var shared_secret: (Array[U8] val | None) = None
  var exchange_hash: (Array[U8] val | None) = None
  var awaiting_host_key_verification: Bool = false

  new create(our_kexinit': Array[U8] val, their_kexinit': Array[U8] val,
    negotiated': SshNegotiatedAlgorithms val)
  =>
    our_kexinit = our_kexinit'
    their_kexinit = their_kexinit'
    negotiated = negotiated'

class SshStateAuth
  """Authentication in progress."""
  let session_id: Array[U8] val
  var methods_remaining: Array[String val] val = recover val Array[String val] end

  new create(session_id': Array[U8] val) =>
    session_id = session_id'

class SshStateConnected
  """Fully authenticated, channels active."""
  let session_id: Array[U8] val
  var rekeying: Bool = false
  var rekey_outbound_queue: Array[Array[U8] val] = Array[Array[U8] val]

  new create(session_id': Array[U8] val) =>
    session_id = session_id'

class SshStateDisconnected
  """Terminal state."""
  let reason: (SshTransportError | None)

  new create(reason': (SshTransportError | None) = None) =>
    reason = reason'

class SshSessionContext
  """Accumulates connection-lifetime facts."""
  var remote_addr: String val = ""
  var remote_version: (String val | None) = None
  var negotiated_algorithms: (SshNegotiatedAlgorithms val | None) = None
  var authenticated_as: (String val | None) = None
  var session_id: (Array[U8] val | None) = None
  var server_host_key: (SshHostKey val | None) = None

primitive SshRoleClient
primitive SshRoleServer
type SshRole is (SshRoleClient | SshRoleServer)
