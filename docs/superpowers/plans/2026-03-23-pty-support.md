# PTY Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PTY request handling, terminal mode transformation (starting with ICRNL), and dedicated channel request callbacks to the SSH server.

**Architecture:** PTY state is an immutable `class val` stored optimistically on `SshChannelState` when a pty-req is parsed. Terminal mode transformations are applied transparently in the session's channel_data dispatch path before reaching the application. The `SshServerNotify` interface gets three new dedicated callbacks (`ssh_pty_request`, `ssh_shell_request`, `ssh_window_change`) while the existing `ssh_channel_request` becomes a catch-all for unrecognised types.

**Tech Stack:** Pony, PonyCheck (property-based testing), lori (TCP), OpenSSL FFI

**Spec:** `docs/superpowers/specs/2026-03-23-pty-support-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `ponyssh/ssh_connection/ssh_pty.pony` | Create | `SshPtyState` class and terminal mode opcode constants |
| `ponyssh/ssh_test/ssh_pty_test.pony` | Create | Property-based tests for PTY parsing and ICRNL transformation |
| `ponyssh/ssh_connection/ssh_channel.pony` | Modify | Add `var pty` field to `SshChannelState` |
| `ponyssh/ssh_transport/ssh_notify.pony` | Modify | Add 3 new callbacks to `SshServerNotify` |
| `ponyssh/ssh_transport/ssh_session.pony` | Modify | Parse pty-req/shell/window-change, dispatch callbacks, apply transforms, clear PTY on reject |
| `ponyssh/ssh_test/ssh_integration_test.pony` | Modify | Add new callback stubs to `_IntegrationServerNotify` |
| `ponyssh/ssh_test/ssh_pubkey_auth_test.pony` | Modify | Add new callback stubs to `_PubkeyServerNotify` |
| `examples/echo-server/main.pony` | Modify | Add new callbacks to `EchoServerNotify`, move shell greeting logic |
| `ponyssh/ssh_test/_test.pony` | Modify | Register new PTY test classes |

---

### Task 1: Create SshPtyState and terminal mode constants

**Files:**
- Create: `ponyssh/ssh_connection/ssh_pty.pony`
- Modify: `ponyssh/ssh_connection/ssh_channel.pony`

- [ ] **Step 1: Create `SshPtyState` class**

Create `ponyssh/ssh_connection/ssh_pty.pony`:

```pony
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
    """Replace lone \\r with \\n. \\r\\n sequences pass through unchanged."""
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

  fun val parse_modes(mode_data: Array[U8] val): Array[(U8, U32)] val ? =>
    """Parse RFC 4254 §8 encoded terminal modes from raw bytes."""
    SshTerminalModes.parse_modes(mode_data)?
```

- [ ] **Step 2: Add `pty` field to `SshChannelState`**

In `ponyssh/ssh_connection/ssh_channel.pony`, add after `var open: Bool = true`:

```pony
  var pty: (SshPtyState val | None) = None
```

No constructor changes needed — it defaults to `None`.

- [ ] **Step 3: Verify it compiles**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh --pass=check`
Expected: compiles successfully (no tests run yet)

- [ ] **Step 4: Commit**

```bash
git add ponyssh/ssh_connection/ssh_pty.pony ponyssh/ssh_connection/ssh_channel.pony
git commit -m "feat: add SshPtyState class with ICRNL transformation and mode parsing"
```

---

### Task 2: Property-based tests for ICRNL transformation

**Files:**
- Create: `ponyssh/ssh_test/ssh_pty_test.pony`
- Modify: `ponyssh/ssh_test/_test.pony`

- [ ] **Step 1: Write ICRNL transformation tests**

Create `ponyssh/ssh_test/ssh_pty_test.pony`:

```pony
use "pony_test"
use "pony_check"
use "../ssh_connection"
use "../ssh_transport"

class iso _TestPtyIcrnlLoneCr is UnitTest
  """Property: when ICRNL is active, output never contains lone \\r."""
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
  """Property: \\r\\n sequences pass through unchanged when ICRNL is active."""
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
  """Lone \\r is replaced with \\n."""
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
```

- [ ] **Step 2: Register tests in `_test.pony`**

In `ponyssh/ssh_test/_test.pony`, add to the `tests` function:

```pony
    test(_TestPtyIcrnlLoneCr)
    test(_TestPtyIcrnlPreservesCrLf)
    test(_TestPtyIcrnlLoneCrReplaced)
    test(_TestPtyNoTransformWithoutIcrnl)
    test(_TestPtyIcrnlDisabledByZeroValue)
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh -o build && ./build/ponyssh`
Expected: All PTY tests pass. Other tests continue to pass.

- [ ] **Step 4: Counterfactual — temporarily break ICRNL to verify property catches it**

In `ssh_pty.pony`, temporarily change `_apply_icrnl` to return `data` unchanged. Run tests.
Expected: `_TestPtyIcrnlLoneCr` fails (finds lone `\r` in output), `_TestPtyIcrnlLoneCrReplaced` fails.
Revert the change after confirming.

- [ ] **Step 5: Commit**

```bash
git add ponyssh/ssh_test/ssh_pty_test.pony ponyssh/ssh_test/_test.pony
git commit -m "test: property-based tests for PTY ICRNL transformation"
```

---

### Task 3: Tests for terminal mode parsing

**Files:**
- Modify: `ponyssh/ssh_test/ssh_pty_test.pony`
- Modify: `ponyssh/ssh_test/_test.pony`

- [ ] **Step 1: Add mode parsing tests**

Append to `ponyssh/ssh_test/ssh_pty_test.pony`:

```pony
class iso _TestPtyModeParseRoundtrip is UnitTest
  """Property: encoded modes round-trip through parse correctly."""
  fun name(): String => "ssh_pty/mode_parse_roundtrip"

  fun apply(h: TestHelper) ? =>
    // Generate a list of (opcode 1-159, value) pairs
    let opcode_gen = recover val Generators.u8_range(1, 159) end
    let value_gen = recover val Generators.u32() end
    let pair_gen = recover val Generators.zip2[U8, U32](opcode_gen, value_gen) end
    let list_gen = recover val
      Generators.iso_seq_of[(U8, U32), Array[(U8, U32)] iso](pair_gen, 0, 20)
    end
    PonyCheck.for_all[Array[(U8, U32)] iso](list_gen, h)(
      {(sample: Array[(U8, U32)] iso, ph: PropertyHelper) ? =>
        let pairs: Array[(U8, U32)] val = consume sample
        // Encode: each pair is opcode (U8) + value (U32 big-endian), then TTY_OP_END
        let w = SshWireWriter
        for (opcode, value) in pairs.values() do
          w.write_byte(opcode)
          w.write_u32(value)
        end
        w.write_byte(SshTerminalModes.tty_op_end())
        let encoded = w.val_bytes()

        // Parse
        let parsed = SshTerminalModes.parse_modes(encoded)?

        // Verify
        ph.assert_eq[USize](parsed.size(), pairs.size())
        var i: USize = 0
        while i < pairs.size() do
          let (exp_op, exp_val) = pairs(i)?
          let (act_op, act_val) = parsed(i)?
          ph.assert_eq[U8](act_op, exp_op)
          ph.assert_eq[U32](act_val, exp_val)
          i = i + 1
        end
      })?

class iso _TestPtyModeParseEmpty is UnitTest
  """Empty modes (just TTY_OP_END) parses to empty array."""
  fun name(): String => "ssh_pty/mode_parse_empty"

  fun apply(h: TestHelper) =>
    let encoded: Array[U8] val = recover val [as U8: 0] end
    try
      let parsed = SshTerminalModes.parse_modes(encoded)?
      h.assert_eq[USize](0, parsed.size())
    else
      h.fail("parse_modes raised error on valid input")
    end
```

- [ ] **Step 2: Register tests in `_test.pony`**

Add to `tests` function:

```pony
    test(_TestPtyModeParseRoundtrip)
    test(_TestPtyModeParseEmpty)
```

- [ ] **Step 3: Run tests**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh -o build && ./build/ponyssh`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add ponyssh/ssh_test/ssh_pty_test.pony ponyssh/ssh_test/_test.pony
git commit -m "test: property-based tests for terminal mode parsing"
```

---

### Task 4: Add new callbacks to SshServerNotify and update all implementors

**Files:**
- Modify: `ponyssh/ssh_transport/ssh_notify.pony`
- Modify: `ponyssh/ssh_test/ssh_integration_test.pony`
- Modify: `ponyssh/ssh_test/ssh_pubkey_auth_test.pony`
- Modify: `examples/echo-server/main.pony`

- [ ] **Step 1: Add callbacks to SshServerNotify interface**

In `ponyssh/ssh_transport/ssh_notify.pony`, add three new behaviors to `SshServerNotify` after `ssh_channel_open_request`:

```pony
  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
```

Also add `use "../ssh_connection"` at the top if not already present (it's already there — verify).

- [ ] **Step 2: Add stub implementations to `_IntegrationServerNotify`**

In `ponyssh/ssh_test/ssh_integration_test.pony`, add to `_IntegrationServerNotify`:

```pony
  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  =>
    if want_reply then session.accept_request(channel_id) end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    if want_reply then session.accept_request(channel_id) end

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
  =>
    None
```

- [ ] **Step 3: Add stub implementations to `_PubkeyServerNotify`**

In `ponyssh/ssh_test/ssh_pubkey_auth_test.pony`, add the same three stub behaviors (identical to Step 2).

- [ ] **Step 4: Update `EchoServerNotify` in echo-server**

In `examples/echo-server/main.pony`, add:

```pony
  be ssh_pty_request(session: SshSession tag, channel_id: U32,
    pty: SshPtyState val, want_reply: Bool)
  =>
    _env.out.print("PTY request: " + pty.term
      + " " + pty.width_chars.string() + "x" + pty.height_rows.string())
    if want_reply then
      session.accept_request(channel_id)
    end

  be ssh_shell_request(session: SshSession tag, channel_id: U32,
    want_reply: Bool)
  =>
    _env.out.print("Shell request")
    if want_reply then
      session.accept_request(channel_id)
    end
    let msg: String val = "Welcome to ponyssh echo server, " + _last_username + "!\r\n"
    let greeting: Array[U8] val = recover val
      let a = Array[U8](msg.size())
      for ch in msg.values() do a.push(ch) end
      a
    end
    session.channel_send(channel_id, greeting)

  be ssh_window_change(session: SshSession tag, channel_id: U32,
    width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
  =>
    _env.out.print("Window change: " + width_chars.string() + "x" + height_rows.string())
```

Also update the existing `ssh_channel_request` to remove the shell-specific logic (it moved to `ssh_shell_request`). The catch-all becomes:

```pony
  be ssh_channel_request(session: SshSession tag, channel_id: U32,
    request_type: String val, want_reply: Bool)
  =>
    _env.out.print("Channel request: " + request_type)
    if want_reply then
      session.accept_request(channel_id)
    end
```

- [ ] **Step 5: Verify it compiles**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh --pass=check && ponyc examples/echo-server --pass=check`
Expected: Both compile successfully.

- [ ] **Step 6: Run tests**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh -o build && ./build/ponyssh`
Expected: All tests pass (no behavior change yet — session still routes everything to `ssh_channel_request`).

- [ ] **Step 7: Commit**

```bash
git add ponyssh/ssh_transport/ssh_notify.pony ponyssh/ssh_test/ssh_integration_test.pony ponyssh/ssh_test/ssh_pubkey_auth_test.pony examples/echo-server/main.pony
git commit -m "feat: add ssh_pty_request, ssh_shell_request, ssh_window_change callbacks"
```

---

### Task 5: Wire up session dispatch for pty-req, shell, and window-change

**Files:**
- Modify: `ponyssh/ssh_transport/ssh_session.pony`

This is the core integration. The `_handle_connected()` method's `channel_request` case currently extracts `request_type` and dispatches everything to `ssh_channel_request`. We change it to match on `request_type` and dispatch to the appropriate callback, parsing request-specific data where needed.

- [ ] **Step 1: Update channel_request dispatch in `_handle_connected()`**

In `ponyssh/ssh_transport/ssh_session.pony`, replace the `channel_request` case (lines 887-898) with:

```pony
    | SshChannelMsgTypes.channel_request() =>
      try
        let r = SshWireReader(payload)
        r.read_byte()?  // msg type
        let recipient_channel = r.read_u32()?
        let request_type = r.read_string_as_str()?
        let want_reply = r.read_bool()?
        match _server_notify
        | let n: SshServerNotify tag =>
          if request_type == "pty-req" then
            let term = r.read_string_as_str()?
            let width_chars = r.read_u32()?
            let height_rows = r.read_u32()?
            let width_pixels = r.read_u32()?
            let height_pixels = r.read_u32()?
            let mode_data = r.read_string()?
            let modes = SshTerminalModes.parse_modes(mode_data)?
            let pty = SshPtyState(term, width_chars, height_rows,
              width_pixels, height_pixels, modes)
            // Store optimistically
            match _channel_manager.get(recipient_channel)
            | let ch: SshChannelState => ch.pty = pty
            end
            n.ssh_pty_request(this, recipient_channel, pty, want_reply)
          elseif request_type == "shell" then
            n.ssh_shell_request(this, recipient_channel, want_reply)
          elseif request_type == "window-change" then
            let width_chars = r.read_u32()?
            let height_rows = r.read_u32()?
            let width_pixels = r.read_u32()?
            let height_pixels = r.read_u32()?
            match _channel_manager.get(recipient_channel)
            | let ch: SshChannelState =>
              match ch.pty
              | let old_pty: SshPtyState val =>
                ch.pty = SshPtyState.with_dimensions(old_pty,
                  width_chars, height_rows, width_pixels, height_pixels)
              end
            end
            n.ssh_window_change(this, recipient_channel,
              width_chars, height_rows, width_pixels, height_pixels)
          else
            n.ssh_channel_request(this, recipient_channel, request_type,
              want_reply)
          end
        end
      end
```

- [ ] **Step 2: Update `reject_request` to clear PTY state**

In `ponyssh/ssh_transport/ssh_session.pony`, modify `reject_request` (lines 207-214) to also clear PTY state:

```pony
  be reject_request(channel_id: U32) =>
    match _state
    | let _: SshStateConnected =>
      match _channel_manager.get(channel_id)
      | let ch: SshChannelState =>
        ch.pty = None
        _send_packet(SshChannelMessages.channel_failure(ch.remote_id))
      end
    end
```

- [ ] **Step 3: Apply terminal mode transformation in channel_data path**

In `ponyssh/ssh_transport/ssh_session.pony`, modify the `channel_data` case (lines 860-868). Replace:

```pony
        _notify_channel_data(recipient_channel, data)
```

with:

```pony
        let transformed = match _channel_manager.get(recipient_channel)
        | let ch: SshChannelState =>
          match ch.pty
          | let pty: SshPtyState val => pty.transform(data)
          | None => data
          end
        | None => data
        end
        _notify_channel_data(recipient_channel, transformed)
```

- [ ] **Step 4: Add `use "../ssh_connection"` import if needed**

Verify `ssh_session.pony` already has `use "../ssh_connection"` — it should since `SshChannelMsgTypes` is used. If `SshPtyState` is in `ssh_connection`, it should be available.

- [ ] **Step 5: Verify it compiles**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh --pass=check && ponyc examples/echo-server --pass=check`
Expected: Compiles successfully.

- [ ] **Step 6: Run tests**

Run: `cd /home/red/projects/ponyssh && ponyc ponyssh -o build && ./build/ponyssh`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add ponyssh/ssh_transport/ssh_session.pony
git commit -m "feat: parse pty-req/shell/window-change and apply ICRNL transformation"
```

---

### Task 6: Integration test with real SSH client

**Files:** None (manual testing)

- [ ] **Step 1: Build and run the echo server**

```bash
cd /home/red/projects/ponyssh && ponyc examples/echo-server -o build && ./build/echo-server
```

- [ ] **Step 2: Connect with a real SSH client**

In another terminal:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no testuser@127.0.0.1
```

Verify:
- Server prints "PTY request: xterm-256color 80x24" (or similar)
- Server prints "Shell request"
- Welcome message appears
- Typing text and pressing Enter works — `buffered.Reader.line()` in the echo server receives complete lines
- Resizing the terminal window prints "Window change: NxM"

- [ ] **Step 3: Commit all changes**

If any fixes were needed during integration testing, commit them.

```bash
git add -u
git commit -m "fix: integration testing fixes for PTY support"
```
