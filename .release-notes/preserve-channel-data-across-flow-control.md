## Preserve channel data across SSH flow control

Outbound channel writes are now delivered completely after the peer replenishes
its receive window instead of silently dropping the unsent suffix.
