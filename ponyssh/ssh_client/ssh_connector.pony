use "lori"
use "../ssh_transport"
use "../ssh_auth"

primitive SshConnector
  fun connect(auth: TCPConnectAuth, config: SshClientConfig val,
    notify: SshClientNotify tag): SshSession tag
  =>
    SshSession.create_client(auth, config, notify)
