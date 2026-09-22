use "pony_test"
use "../ssh_transport"
use "../ssh_error"

class \nodoc\ iso _TestServerConfigRejectsBadKey is UnitTest
  fun name(): String => "ssh_transport/server_config/rejects_bad_key"

  fun apply(h: TestHelper) =>
    let garbage: Array[U8] val = "SECRET-PEM-INPUT".array()
    match MakeSshServerConfig(garbage, "127.0.0.1", "22")
    | SshServerHostKeyLoadFailed =>
      h.assert_eq[String]("server host key could not be loaded",
        SshServerHostKeyLoadFailed.string())
    | let _: SshServerConfig val => h.fail("invalid PEM accepted")
    | let _: SshServerChannelWindowTooSmall =>
      h.fail("invalid PEM reported as a window error")
    end

class \nodoc\ iso _TestServerConfigChannelWindow is UnitTest
  fun name(): String => "ssh_transport/server_config/channel_window"

  fun apply(h: TestHelper) =>
    for size in [as U32: 0; 255].values() do
      match MakeSshServerConfig(_TestEd25519Pem(), "127.0.0.1", "22"
        where channel_window' = size)
      | let err: SshServerChannelWindowTooSmall =>
        h.assert_eq[U32](size, err.given)
        h.assert_eq[U32](256, err.minimum)
        if size == 255 then
          h.assert_eq[String](
            "server channel window 255 is below minimum 256", err.string())
        end
      | let _: SshServerConfig val => h.fail("small window accepted")
      | SshServerHostKeyLoadFailed => h.fail("valid PEM rejected")
      end
    end

    match MakeSshServerConfig(_TestEd25519Pem(), "127.0.0.1", "22"
      where channel_window' = 256)
    | let config: SshServerConfig val =>
      h.assert_eq[U32](256, config.channel_window)
    | let err: SshServerConfigError => h.fail(err.string())
    end

class \nodoc\ iso _TestServerConfigBadKeyPrecedesWindow is UnitTest
  fun name(): String => "ssh_transport/server_config/bad_key_precedes_window"

  fun apply(h: TestHelper) =>
    match MakeSshServerConfig("invalid PEM".array()
      where channel_window' = 255)
    | SshServerHostKeyLoadFailed => None
    | let _: SshServerChannelWindowTooSmall =>
      h.fail("window error preceded host key error")
    | let _: SshServerConfig val => h.fail("invalid settings accepted")
    end

class \nodoc\ iso _TestServerConfigPreservesFields is UnitTest
  fun name(): String => "ssh_transport/server_config/preserves_fields"

  fun apply(h: TestHelper) =>
    let pem = _TestEd25519Pem()
    let prefs = SshAlgorithmPreferences(where
      kex' = recover val [as String val: "kex-choice"] end,
      host_key' = recover val [as String val: "host-choice"] end,
      cipher_client_to_server' =
        recover val [as String val: "client-cipher"] end,
      cipher_server_to_client' =
        recover val [as String val: "server-cipher"] end,
      mac_client_to_server' = recover val [as String val: "client-mac"] end,
      mac_server_to_client' = recover val [as String val: "server-mac"] end)

    match MakeSshServerConfig(pem, "192.0.2.1", "2223", prefs
      where channel_window' = 257)
    | let config: SshServerConfig val =>
      h.assert_array_eq[U8](pem, config.host_key_pem)
      h.assert_eq[String]("192.0.2.1", config.listen_host)
      h.assert_eq[String]("2223", config.listen_port)
      h.assert_eq[U32](257, config.channel_window)
      h.assert_array_eq[String val](prefs.kex, config.algorithms.kex)
      h.assert_array_eq[String val](prefs.host_key,
        config.algorithms.host_key)
      h.assert_array_eq[String val](prefs.cipher_client_to_server,
        config.algorithms.cipher_client_to_server)
      h.assert_array_eq[String val](prefs.cipher_server_to_client,
        config.algorithms.cipher_server_to_client)
      h.assert_array_eq[String val](prefs.mac_client_to_server,
        config.algorithms.mac_client_to_server)
      h.assert_array_eq[String val](prefs.mac_server_to_client,
        config.algorithms.mac_server_to_client)
    | let err: SshServerConfigError => h.fail(err.string())
    end

class \nodoc\ iso _TestServerConfigPreservesDefaults is UnitTest
  fun name(): String => "ssh_transport/server_config/preserves_defaults"

  fun apply(h: TestHelper) =>
    let pem = _TestEd25519Pem()
    let defaults = SshDefaultAlgorithms.preferences()
    match MakeSshServerConfig(pem)
    | let config: SshServerConfig val =>
      h.assert_array_eq[U8](pem, config.host_key_pem)
      h.assert_eq[String]("127.0.0.1", config.listen_host)
      h.assert_eq[String]("22", config.listen_port)
      h.assert_eq[U32](0x200000, config.channel_window)
      h.assert_array_eq[String val](defaults.kex, config.algorithms.kex)
      h.assert_array_eq[String val](defaults.host_key,
        config.algorithms.host_key)
      h.assert_array_eq[String val](defaults.cipher_client_to_server,
        config.algorithms.cipher_client_to_server)
      h.assert_array_eq[String val](defaults.cipher_server_to_client,
        config.algorithms.cipher_server_to_client)
      h.assert_array_eq[String val](defaults.mac_client_to_server,
        config.algorithms.mac_client_to_server)
      h.assert_array_eq[String val](defaults.mac_server_to_client,
        config.algorithms.mac_server_to_client)
    | let err: SshServerConfigError => h.fail(err.string())
    end
