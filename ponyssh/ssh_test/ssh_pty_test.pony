use "pony_test"
use "pony_check"
use "../ssh_connection"
use "../ssh_transport"

class iso _TestPtyIcrnlLoneCr is UnitTest
  """Property: when ICRNL is active, output never contains lone \r."""
  fun name(): String => "ssh_pty/icrnl_no_lone_cr"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(sample: Array[U8] iso, ph: PropertyHelper) =>
        let data: Array[U8] val = consume sample
        let modes: Array[(U8, U32)] val = recover val
          let a = Array[(U8, U32)]
          a.push((SshTerminalModes.icrnl(), 1))
          a
        end
        let pty = SshPtyState("xterm", 80, 24, 0, 0, modes)
        let result = pty.transform(data)

        // Check: no lone \r in output
        var i: USize = 0
        while i < result.size() do
          try
            if result(i)? == '\r' then
              // Must be followed by \n
              ph.assert_true(
                ((i + 1) < result.size()) and (result(i + 1)? == '\n'),
                "lone \\r found at index " + i.string())
            end
          end
          i = i + 1
        end
      })?

class iso _TestPtyIcrnlPreservesCrLf is UnitTest
  """Property: \r\n sequences pass through unchanged when ICRNL is active."""
  fun name(): String => "ssh_pty/icrnl_preserves_crlf"

  fun apply(h: TestHelper) =>
    let modes: Array[(U8, U32)] val = recover val
      let a = Array[(U8, U32)]
      a.push((SshTerminalModes.icrnl(), 1))
      a
    end
    let pty = SshPtyState("xterm", 80, 24, 0, 0, modes)

    // \r\n should pass through
    let input: Array[U8] val = recover val [as U8: 'h'; 'i'; '\r'; '\n'] end
    let result = pty.transform(input)
    h.assert_eq[USize](4, result.size())
    try
      h.assert_eq[U8]('h', result(0)?)
      h.assert_eq[U8]('i', result(1)?)
      h.assert_eq[U8]('\r', result(2)?)
      h.assert_eq[U8]('\n', result(3)?)
    else
      h.fail("index out of bounds")
    end

class iso _TestPtyIcrnlLoneCrReplaced is UnitTest
  """Lone \r is replaced with \n."""
  fun name(): String => "ssh_pty/icrnl_lone_cr_replaced"

  fun apply(h: TestHelper) =>
    let modes: Array[(U8, U32)] val = recover val
      let a = Array[(U8, U32)]
      a.push((SshTerminalModes.icrnl(), 1))
      a
    end
    let pty = SshPtyState("xterm", 80, 24, 0, 0, modes)

    // Lone \r should become \n
    let input: Array[U8] val = recover val [as U8: 'h'; 'i'; '\r'] end
    let result = pty.transform(input)
    h.assert_eq[USize](3, result.size())
    try
      h.assert_eq[U8]('h', result(0)?)
      h.assert_eq[U8]('i', result(1)?)
      h.assert_eq[U8]('\n', result(2)?)
    else
      h.fail("index out of bounds")
    end

class iso _TestPtyNoTransformWithoutIcrnl is UnitTest
  """Data passes through unchanged when ICRNL is not set."""
  fun name(): String => "ssh_pty/no_transform_without_icrnl"

  fun apply(h: TestHelper) ? =>
    let gen = recover val
      Generators.iso_seq_of[U8, Array[U8] iso](Generators.u8(), 0, 256)
    end
    PonyCheck.for_all[Array[U8] iso](gen, h)(
      {(sample: Array[U8] iso, ph: PropertyHelper) =>
        let data: Array[U8] val = consume sample
        let modes: Array[(U8, U32)] val = recover val Array[(U8, U32)] end
        let pty = SshPtyState("xterm", 80, 24, 0, 0, modes)
        let result = pty.transform(data)

        // Should be identical
        ph.assert_array_eq[U8](result, data)
      })?

class iso _TestPtyIcrnlDisabledByZeroValue is UnitTest
  """ICRNL with value 0 means disabled — data passes through unchanged."""
  fun name(): String => "ssh_pty/icrnl_disabled_by_zero"

  fun apply(h: TestHelper) =>
    let modes: Array[(U8, U32)] val = recover val
      let a = Array[(U8, U32)]
      a.push((SshTerminalModes.icrnl(), 0))
      a
    end
    let pty = SshPtyState("xterm", 80, 24, 0, 0, modes)

    let input: Array[U8] val = recover val [as U8: 'h'; 'i'; '\r'] end
    let result = pty.transform(input)
    h.assert_eq[USize](3, result.size())
    try
      h.assert_eq[U8]('\r', result(2)?)
    else
      h.fail("index out of bounds")
    end
