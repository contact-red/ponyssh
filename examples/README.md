# Examples

Each subdirectory is a self-contained Pony program demonstrating a part of the ponyssh library.

## [echo-server](echo-server/)

Listens on port 2222, authenticates a client by password or by an authorized public key, and writes a coloured greeting after a shell request. It does not read the client's input. Its `SshServerNotify` handles listener status, authentication, channel authorization, and send results; it retains a blocked suffix and retries after a window hint. Start here if you're new to the library.
