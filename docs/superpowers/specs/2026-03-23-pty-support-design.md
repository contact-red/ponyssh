# PTY Support Design

## Problem

SSH clients send `\r` when the user presses Enter. Pony's `buffered.Reader.line()` splits on `\n` or `\r\n`, not lone `\r`. The server needs to handle PTY requests and apply terminal mode transformations (like ICRNL) so that application code using standard line-reading tools works correctly.

## Design Decisions

- **PTY state embedded in channel state** — `SshChannelState` gets an optional `pty` field, set when a pty-req is accepted. Non-PTY channels remain raw.
- **Transparent transformation** — `ssh_channel_data` delivers transformed data. Applications wanting raw bytes use non-PTY channels.
- **Separate notify callbacks** — dedicated `ssh_pty_request`, `ssh_shell_request`, `ssh_window_change` callbacks instead of a union type. Unrecognised request types still route to the existing `ssh_channel_request` catch-all.
- **Transform in session dispatch** — terminal mode transformations applied in `_handle_connected()` channel_data path, before calling `_notify_channel_data`.
- **Architecture supports all modes, implementation is incremental** — `SshPtyState` stores all client-sent modes. Transformation logic handles only the modes we've implemented; unrecognised opcodes are ignored.

## Data Structures

### SshPtyState

New class in `ssh_connection/ssh_pty.pony`:

```pony
class SshPtyState
  let term: String val
  let width_chars: U32
  let height_rows: U32
  let width_pixels: U32
  let height_pixels: U32
  let modes: Array[(U8, U32)] val
```

- `modes` stores every `(opcode, value)` pair from the RFC 4254 §8 encoded terminal modes string.
- `term` is the TERM environment variable value (e.g. "xterm-256color").
- Dimension fields are updated in place on window-change.

### SshChannelState changes

```pony
var pty: (SshPtyState | None) = None
```

Set when a pty-req is accepted. Stays `None` for non-PTY channels.

## Message Parsing

### pty-req (RFC 4254 §6.2)

After the common channel_request header (recipient_channel, request_type, want_reply), the payload contains:

```
string    TERM environment variable value
uint32    terminal width, characters
uint32    terminal height, rows
uint32    terminal width, pixels
uint32    terminal height, pixels
string    encoded terminal modes
```

The encoded terminal modes string is a sequence of `(opcode: U8, value: U32)` pairs terminated by `TTY_OP_END (0)`.

Parsed in `_handle_connected()` at the `channel_request` case when `request_type == "pty-req"`. The wire reader `r` already has the correct position after reading the common fields.

### window-change (RFC 4254 §6.7)

Channel request with `request_type == "window-change"`, `want_reply` always false. Payload after common header:

```
uint32    terminal width, characters
uint32    terminal height, rows
uint32    terminal width, pixels
uint32    terminal height, pixels
```

Updates dimension fields on the channel's existing `SshPtyState`. No accept/reject needed.

### shell

Channel request with `request_type == "shell"`. No additional payload beyond the common header fields.

## Notify Interface Changes

New callbacks on `SshServerNotify`:

```pony
be ssh_pty_request(session: SshSession tag, channel_id: U32,
  pty: SshPtyState val, want_reply: Bool)

be ssh_shell_request(session: SshSession tag, channel_id: U32,
  want_reply: Bool)

be ssh_window_change(session: SshSession tag, channel_id: U32,
  width_chars: U32, height_rows: U32, width_pixels: U32, height_pixels: U32)
```

- Server accepts/rejects pty-req and shell via existing `session.accept_request(channel_id)` / `session.reject_request(channel_id)`.
- When pty-req is accepted, session stores `SshPtyState` on the channel.
- When rejected, no PTY state is set — channel remains raw.
- `ssh_channel_request` remains as catch-all for unrecognised request types.

## Terminal Mode Transformation

### Data path

In `_handle_connected()`, channel_data case (msg type 94): after decoding `data`, look up the channel's PTY state. If present, call `pty.transform(data)` and pass the result to `_notify_channel_data`. If no PTY state, pass data through unchanged.

### Transform method

```pony
fun val transform(data: Array[U8] val): Array[U8] val
```

Lives on `SshPtyState`. Applies active transformations based on stored modes. Unrecognised opcodes are ignored (no transformation applied).

### ICRNL (opcode 13)

First mode to implement. When value is non-zero: replace lone `\r` bytes with `\n`. `\r\n` sequences pass through unchanged (already have the `\n`).

## Files Changed

Modified:
- `ssh_connection/ssh_channel.pony` — add optional `pty` field to `SshChannelState`
- `ssh_transport/ssh_notify.pony` — add `ssh_pty_request`, `ssh_shell_request`, `ssh_window_change` to `SshServerNotify`
- `ssh_transport/ssh_session.pony` — parse pty-req/shell/window-change, dispatch to new callbacks, store PTY state on accept, apply transformations in channel data path

Created:
- `ssh_connection/ssh_pty.pony` — `SshPtyState` class
- `ssh_test/ssh_pty_test.pony` — property-based tests

No changes to `SshClientNotify`.

## Testing

### PTY request parsing

Property-based tests using PonyCheck. Generate valid pty-req payloads with random terminal types, dimensions, and mode lists. Verify round-trip: build payload with `SshWireWriter`, parse back, confirm all fields match. Invalid generators: truncated payloads, malformed mode encodings (missing TTY_OP_END, truncated value bytes).

### Terminal mode transformation

Property-based tests on `SshPtyState.transform()`. For ICRNL:
- Lone `\r` → `\n`
- `\r\n` passes through unchanged
- `\n` passes through unchanged
- Data with no `\r` passes through unchanged
- Property: output never contains lone `\r` when ICRNL is active

### Counterfactual verification

After tests pass, temporarily disable ICRNL transformation and confirm the "no lone `\r`" property fails.

### Integration

Test with real native SSH client to verify pty-req/shell/window-change sequence works end-to-end before committing.
