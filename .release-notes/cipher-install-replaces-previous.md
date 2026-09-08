## Stop encrypting under a retired key after a cipher change at rekey

A key re-exchange that negotiated a different cipher left the previous cipher installed, and packets kept being encrypted under the key that had just been rotated away. Under strict key exchange the packet sequence number resets to zero at that same point, and for chacha20-poly1305 the sequence number is the nonce, so traffic after the rekey reused nonces from the start of the session. Anyone who recorded the earlier traffic can recover the plaintext of both, and the repeated Poly1305 one-time keys allow forging a packet. The same omission on the receiving side left a partially decrypted packet in place across the change.

Installing a cipher now replaces the previous one on both the packet reader and the packet writer.
