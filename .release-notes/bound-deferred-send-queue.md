## Bound the send queue held open during a rekey

Between our SSH_MSG_KEXINIT and our SSH_MSG_NEWKEYS, outbound packets are deferred so that only key-exchange traffic goes on the wire. A peer starts that window by sending its own SSH_MSG_KEXINIT and ends it by completing the exchange. A peer that started one and then stopped left the window open, and every packet queued in it was held for the life of the connection, including the replies its own traffic produced. Memory grew at whatever rate the peer chose to send.

The queue is now limited to 1024 packets and 4 MiB, and a session that exceeds either limit disconnects.
