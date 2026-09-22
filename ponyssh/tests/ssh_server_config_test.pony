use "pony_test"
use "../ssh_transport"

class iso _TestServerConfigRejectsBadKey is UnitTest
  """
  SshServerConfig validates the host key at construction. An unparseable key
  must be rejected up front rather than silently dropping every connection at
  key exchange; a valid key must construct.
  """
  fun name(): String => "ssh_transport/server_config/rejects_bad_key"

  fun apply(h: TestHelper) =>
    let garbage: Array[U8] val = "this is not a valid PEM private key".array()
    try
      SshServerConfig(garbage, "127.0.0.1", "22")?
      h.fail("expected construction to fail on an invalid host key")
    else
      h.assert_true(true)  // expected: rejected
    end

    // A valid host key must still construct successfully.
    try
      SshServerConfig(_TestEd25519Pem(), "127.0.0.1", "22")?
    else
      h.fail("a valid host key should construct")
    end

class \nodoc\ iso _TestServerConfigChannelWindow is UnitTest
  fun name(): String => "ssh_transport/server_config/channel_window"

  fun apply(h: TestHelper) =>
    for size in [as U32: 0; 255].values() do
      try
        SshServerConfig(_TestEd25519Pem(), "127.0.0.1", "22"
          where channel_window' = size)?
        h.fail("undersized channel window accepted")
      end
    end

    try
      let config = SshServerConfig(_TestEd25519Pem(), "127.0.0.1", "22"
        where channel_window' = 256)?
      h.assert_eq[U32](256, config.channel_window)
      let default_config = SshServerConfig(_TestEd25519Pem())?
      h.assert_eq[U32](0x200000, default_config.channel_window)
    else
      h.fail("valid channel window rejected")
    end
