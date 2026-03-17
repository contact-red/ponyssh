use "../ssh_crypto"
use "../ssh_error"

actor _SshKexWorker
  """
  Short-lived actor for CPU-intensive key exchange computation.
  Sends result back to session via iso messaging.
  """
  let _session: SshSession tag

  new create(session: SshSession tag, algorithm: String val,
    peer_public: Array[U8] val)
  =>
    _session = session
    _compute(algorithm, peer_public)

  be _compute(algorithm: String val, peer_public: Array[U8] val) =>
    match algorithm
    | "curve25519-sha256" =>
      try
        let kex = SshKexCurve25519.create()?
        let our_public = kex.public_key()
        match kex.derive_shared_secret(peer_public)
        | let secret: Array[U8] val =>
          _session._kex_computed(our_public, secret)
        | let err: SshCryptoError =>
          _session._kex_failed(SshKexFailed(err))
        end
      else
        _session._kex_failed(SshKexFailed(SshKeyInvalid))
      end
    else
      // Unsupported algorithm — should be unreachable after negotiation
      _session._kex_failed(SshKexFailed(SshKeyInvalid))
    end
