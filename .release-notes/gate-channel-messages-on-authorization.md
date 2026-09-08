## Refuse channel messages until the channel open is authorized

Channel state is allocated when SSH_MSG_CHANNEL_OPEN is parsed, but the consumer's decision on that open arrives asynchronously, and a whole TCP segment is dispatched before the decision can run. A peer that sent SSH_MSG_CHANNEL_REQUEST and SSH_MSG_CHANNEL_DATA immediately behind the open reached the consumer's shell, exec, pty-req and channel-data handlers for a channel the consumer went on to reject. Per-channel-type authorization written in `ssh_channel_open_request` was bypassable for one round of requests and data.

Channel requests, data and window adjustments naming a channel whose open has not been authorized are now refused. A request that asked for a reply gets SSH_MSG_CHANNEL_FAILURE.
