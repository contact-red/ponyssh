## Remove clear_encrypt_ctx and clear_decrypt_ctx

`SshPacketWriter.clear_encrypt_ctx` and `SshPacketReader.clear_decrypt_ctx` are gone. Installing a cipher now replaces the one already installed, so there is nothing left for a separate clear step to do. Code calling either method can delete the call.

`SshTransportError` has three new members: `SshUnexpectedMessage`, `SshTooManyAuthAttempts` and `SshPendingSendsExceeded`. Code matching exhaustively on `SshTransportError` needs to handle them.
