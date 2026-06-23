use "lori"
use "../ssh_transport"
use "../ssh_auth"

primitive SshConnector
  """Entry point for client code: opens an outbound SSH session."""
  fun connect(auth: TCPConnectAuth, config: SshClientConfig val,
    notify: SshClientNotify tag): SshSession tag
  =>
    """
    Connect to the server in `config`, driving the session through `notify`.
    Returns the session tag so the caller can issue commands once it is ready.
    """
    SshSession.create_client(auth, config, notify)
