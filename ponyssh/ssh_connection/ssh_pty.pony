use "../ssh_transport"

primitive SshTerminalModes
  """RFC 4254 §8 terminal mode opcodes and parsing."""
  fun tty_op_end(): U8 => 0
  fun icrnl(): U8 => 13

  fun parse_modes(mode_data: Array[U8] val): Array[(U8, U32)] val ? =>
    """Parse encoded terminal modes from raw bytes."""
    recover val
      let r = SshWireReader(mode_data)
      let result = Array[(U8, U32)]
      while r.remaining() > 0 do
        let opcode = r.read_byte()?
        if opcode == tty_op_end() then break end
        if (opcode >= 1) and (opcode <= 159) then
          let value = r.read_u32()?
          result.push((opcode, value))
        else
          break
        end
      end
      result
    end

class val SshPtyState
  """Immutable PTY state. Replaced (not mutated) on window-change."""
  let term: String val
  let width_chars: U32
  let height_rows: U32
  let width_pixels: U32
  let height_pixels: U32
  let modes: Array[(U8, U32)] val

  new val create(term': String val, width_chars': U32, height_rows': U32,
    width_pixels': U32, height_pixels': U32, modes': Array[(U8, U32)] val)
  =>
    term = term'
    width_chars = width_chars'
    height_rows = height_rows'
    width_pixels = width_pixels'
    height_pixels = height_pixels'
    modes = modes'

  new val none() =>
    term = ""
    width_chars = 0
    height_rows = 0
    width_pixels = 0
    height_pixels = 0
    modes = []


  new val with_dimensions(original: SshPtyState val, width_chars': U32,
    height_rows': U32, width_pixels': U32, height_pixels': U32)
  =>
    """Create a new SshPtyState with updated dimensions, keeping term and modes."""
    term = original.term
    width_chars = width_chars'
    height_rows = height_rows'
    width_pixels = width_pixels'
    height_pixels = height_pixels'
    modes = original.modes

  fun val mode_value(opcode: U8): U32 =>
    """Look up a mode value by opcode. Returns 0 if not found."""
    for (op, value) in modes.values() do
      if op == opcode then return value end
    end
    0

  fun val transform(data: Array[U8] val): Array[U8] val =>
    """Apply active terminal mode transformations to incoming data."""
    var result = data
    if mode_value(SshTerminalModes.icrnl()) != 0 then
      result = _apply_icrnl(result)
    end
    result

  fun val _apply_icrnl(data: Array[U8] val): Array[U8] val =>
    """Replace lone \r with \n. \r\n sequences pass through unchanged."""
    // Fast path: if no \r present, return unchanged
    var has_cr: Bool = false
    for byte in data.values() do
      if byte == '\r' then has_cr = true; break end
    end
    if not has_cr then return data end

    recover val
      let out = Array[U8](data.size())
      var i: USize = 0
      while i < data.size() do
        try
          let byte = data(i)?
          if byte == '\r' then
            // Check if next byte is \n
            if ((i + 1) < data.size()) and (data(i + 1)? == '\n') then
              // \r\n — pass through both
              out.push('\r')
              out.push('\n')
              i = i + 2
            else
              // Lone \r — replace with \n
              out.push('\n')
              i = i + 1
            end
          else
            out.push(byte)
            i = i + 1
          end
        else
          break
        end
      end
      out
    end
