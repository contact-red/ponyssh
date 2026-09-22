# Examples

Each subdirectory is a self-contained Pony program demonstrating a part of the ponyssh library.

## [echo-server](echo-server/)

Listens on port 2222, authenticates a client by password or by an authorized public key, and on a shell request writes a coloured greeting to the client's terminal; it does not read the client's input. Demonstrates `SshListener` with an `SshServerNotify` that prints the bind outcome (`ssh_listener_started` / `ssh_listener_failed`), states its auth policy (`validate_password` / `validate_publickey`), and grants the channel, PTY and shell requests the default callbacks reject. Build it with `make echo-server` from the repository root. Start here if you're new to the library.
