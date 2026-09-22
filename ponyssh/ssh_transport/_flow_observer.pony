trait tag _SshFlowObserver
  be _flow_admitted(payload: Array[U8] val)
  be _flow_barrier()
  be _flow_snapshot_result(pending_packets: USize, pending_bytes: USize,
    blocked: Bool, remote_window: U32, terminated: Bool)
