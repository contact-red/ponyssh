use "pony_test"
use "pony_check"
use "../ssh_connection"
use "../ssh_error"

class \nodoc\ iso _TestChannelPeerWindowProperty is UnitTest
  fun name(): String => "ssh_channel/peer_window_property"

  fun apply(h: TestHelper) ? =>
    let gen = recover val Generators.u32() end
    PonyCheck.for_all[U32](gen, h)(
      {(sample: U32, ph: PropertyHelper) =>
        for advertised in [as U32: 0; 1; 255; 256; 257; 32767
          32768; 32769; U32.max_value(); sample].values() do
          let accepted_mgr = SshChannelManager
          let accepted = accepted_mgr.accept_channel(0, 7, 1024,
            advertised, "session")
          let confirmed_mgr = SshChannelManager
          let opened = confirmed_mgr.open_channel("session")
          let confirmed = confirmed_mgr.confirm_channel(opened, 7,
            1024, advertised)
          if advertised < 256 then
            match accepted
            | let _: SshChannelUnsupportedPacketSize => None
            | let _: U32 => ph.fail("unsupported packet size accepted")
            end
            ph.assert_eq[USize](0, accepted_mgr.channel_count())
            match confirmed
            | let _: SshChannelUnsupportedPacketSize => None
            | let _: SshChannelError =>
              ph.fail("wrong confirmation error")
            | None => ph.fail("unsupported confirmation accepted")
            end
            match confirmed_mgr.get(opened)
            | let ch: SshChannelState => ph.assert_false(ch.authorized)
            | None => ph.fail("rejected confirmation lost pending channel")
            end
          else
            let expected = advertised.min(32768)
            match accepted
            | let id: U32 =>
              match accepted_mgr.get(id)
              | let ch: SshChannelState =>
                ph.assert_eq[U32](expected, ch.max_packet_size)
              | None => ph.fail("accepted channel missing")
              end
            | let _: SshChannelUnsupportedPacketSize =>
              ph.fail("supported packet size rejected")
            end
            ph.assert_true(confirmed is None)
            match confirmed_mgr.get(opened)
            | let ch: SshChannelState =>
              ph.assert_true(ch.authorized)
              ph.assert_eq[U32](expected, ch.max_packet_size)
            | None => ph.fail("confirmed channel missing")
            end
          end
        end

        for amount in [as U32: 0; 1023; 1024; 1025
          sample % 2049].values() do
          let mgr = SshChannelManager
          let id = mgr.open_channel("session")
          mgr.confirm_channel(id, 7, 1024, 256)
          let result = mgr.channel_data_admitted(id, amount.usize())
          if amount <= 1024 then
            ph.assert_true(result is None)
          else
            match result
            | SshWindowExhausted => None
            | let _: SshChannelError => ph.fail("wrong debit error")
            | None => ph.fail("debit exceeded credit")
            end
          end
          match mgr.get(id)
          | let ch: SshChannelState =>
            let remaining: U32 = if amount <= 1024 then
              1024 - amount else 1024 end
            ph.assert_eq[U32](remaining, ch.remote_window)
          | None => ph.fail("debit removed channel")
          end
        end

        for (credit, grant) in [as (U32, U32):
          (1024, 0); (1024, 17); (U32.max_value() - 1, 2)
          (sample, sample)].values() do
          let mgr = SshChannelManager
          let id = mgr.open_channel("session")
          mgr.confirm_channel(id, 7, credit, 256)
          mgr.window_adjust(id, grant)
          let sum = credit.u64() + grant.u64()
          let expected = sum.min(U32.max_value().u64()).u32()
          match mgr.get(id)
          | let ch: SshChannelState =>
            ph.assert_eq[U32](expected, ch.remote_window)
          | None => ph.fail("adjust removed channel")
          end
        end
      })?
