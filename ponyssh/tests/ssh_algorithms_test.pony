use "pony_test"
use "../ssh_transport"
use "../ssh_error"

class iso _TestAlgoNegotiateFirstMatch is UnitTest
  fun name(): String => "ssh_transport/algorithms/negotiate_first_match"

  fun apply(h: TestHelper) =>
    // Client prefers [A, B, C], server supports [C, B]. Result should be B.
    let client = SshAlgorithmPreferences(
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end)
    let server = SshAlgorithmPreferences(
      recover val ["C"; "B"] end,
      recover val ["C"; "B"] end,
      recover val ["C"; "B"] end,
      recover val ["C"; "B"] end,
      recover val ["C"; "B"] end,
      recover val ["C"; "B"] end)
    match SshAlgorithmNegotiation.negotiate(client, server)
    | let r: SshNegotiatedAlgorithms val =>
      h.assert_eq[String val](r.kex, "B")
      h.assert_eq[String val](r.host_key, "B")
      h.assert_eq[String val](r.cipher_c2s, "B")
      h.assert_eq[String val](r.cipher_s2c, "B")
      h.assert_eq[String val](r.mac_c2s, "B")
      h.assert_eq[String val](r.mac_s2c, "B")
    | SshAlgorithmNegotiationFailed =>
      h.fail("expected negotiation to succeed")
    end

class iso _TestAlgoNegotiateNoOverlap is UnitTest
  fun name(): String => "ssh_transport/algorithms/negotiate_no_overlap"

  fun apply(h: TestHelper) =>
    // Client prefers [A, B], server supports [C, D]. Should fail.
    let client = SshAlgorithmPreferences(
      recover val ["A"; "B"] end,
      recover val ["A"; "B"] end,
      recover val ["A"; "B"] end,
      recover val ["A"; "B"] end,
      recover val ["A"; "B"] end,
      recover val ["A"; "B"] end)
    let server = SshAlgorithmPreferences(
      recover val ["C"; "D"] end,
      recover val ["C"; "D"] end,
      recover val ["C"; "D"] end,
      recover val ["C"; "D"] end,
      recover val ["C"; "D"] end,
      recover val ["C"; "D"] end)
    match SshAlgorithmNegotiation.negotiate(client, server)
    | let _: SshNegotiatedAlgorithms val =>
      h.fail("expected negotiation to fail")
    | SshAlgorithmNegotiationFailed =>
      h.assert_true(true)
    end

class iso _TestAlgoNegotiateIdenticalLists is UnitTest
  fun name(): String => "ssh_transport/algorithms/negotiate_identical_lists"

  fun apply(h: TestHelper) =>
    // Both have [A, B, C]. Result should be A (first).
    let prefs = SshAlgorithmPreferences(
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end,
      recover val ["A"; "B"; "C"] end)
    match SshAlgorithmNegotiation.negotiate(prefs, prefs)
    | let r: SshNegotiatedAlgorithms val =>
      h.assert_eq[String val](r.kex, "A")
      h.assert_eq[String val](r.host_key, "A")
      h.assert_eq[String val](r.cipher_c2s, "A")
      h.assert_eq[String val](r.cipher_s2c, "A")
      h.assert_eq[String val](r.mac_c2s, "A")
      h.assert_eq[String val](r.mac_s2c, "A")
    | SshAlgorithmNegotiationFailed =>
      h.fail("expected negotiation to succeed")
    end

class iso _TestAlgoNegotiateDefaults is UnitTest
  fun name(): String => "ssh_transport/algorithms/negotiate_defaults"

  fun apply(h: TestHelper) =>
    // Negotiate default preferences against themselves; first choices win.
    let defaults = SshDefaultAlgorithms.preferences()
    match SshAlgorithmNegotiation.negotiate(defaults, defaults)
    | let r: SshNegotiatedAlgorithms val =>
      h.assert_eq[String val](r.kex, "curve25519-sha256")
      h.assert_eq[String val](r.host_key, "ssh-ed25519")
      h.assert_eq[String val](r.cipher_c2s, "chacha20-poly1305@openssh.com")
      h.assert_eq[String val](r.cipher_s2c, "chacha20-poly1305@openssh.com")
      h.assert_eq[String val](r.mac_c2s, "hmac-sha2-256")
      h.assert_eq[String val](r.mac_s2c, "hmac-sha2-256")
    | SshAlgorithmNegotiationFailed =>
      h.fail("expected default negotiation to succeed")
    end
