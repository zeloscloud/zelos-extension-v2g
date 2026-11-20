# CLAUDE.md: zelos-extension-v2g

ISO 15118 / DIN 70121 charging links in Zelos: SLAC, SDP, V2GTP and every decoded message,
live from a network interface or from a pcap. Capture and decode are `zelos-packet`'s (Rust);
this extension is the configuration, actions and CLI around it.

## Layout

| Path | Role |
|------|------|
| `main.py` | Entry point: app mode (no subcommand) and the CLI group. Re-exports `ACTION_PREFIX`. |
| `decode.py` | The one seam onto the V2G decoder: `V2gConfig.kwargs()`, the counter names, `require()`. |
| `capture.py` | `trace_layout`, `parse_interfaces`, `CaptureSession`, `make_decoder`, `replay_pcap`, permission probe and remediation text. |
| `converter.py` | `convert_pcap`: capture file to `.trz`, own namespace, no agent. |
| `actions.py` | The `V2G/*` actions, all read-only free functions. |
| `cli/app.py` | App mode from `config.json`: validate, `init_sdk`, replay or live sessions. |
| `cli/commands.py` | `interfaces`, `check`, `capture`, `replay`, `convert`. |
| `pkg.py` | Import probe for `zelos_packet`; `module()` is the test seam. |
| `demo/` | The bundled demo capture. |

## Rules

- **No decode here.** Field names, units, value tables, TLS and reassembly are `zelos-packet`'s.
  A decode bug is fixed there; this repo then moves its exact pin.
- **One tree shape.** `capture.trace_layout(prefix, capture)` returns the trace source and the
  event-name prefix. Live capture, replay and conversion all call it; nothing else builds a name.
- **One set of decoder keywords.** `decode.V2gConfig.kwargs()` is the only place `v2g` and
  `tls_keylog` are spelled.
- **Live rows never pass through this process.** `PacketCapture` supervises the capture helper,
  which streams to the agent itself. `--file` under `capture` records only the extension's log.
- **Start policy.** Any interface that fails to open fails the whole start with one ERROR line;
  the supervisor does not restart, so that line is the user's whole experience.
- **No capture filter.** The agent's own traffic is excluded by the package default. The decoder
  needs SLAC (0x88E1), SDP and V2G over either IP version, and key log datagrams on any UDP port.
- **Secrets.** A key log path is passed through and logged; the file is never read here.

## Testing

```bash
just check    # ruff format check and lint
just test     # pytest
just package  # zelos extensions package .
```

`tests/conftest.py` stubs `zelos_packet` with the real constructor signatures spelled out, so a
drifting keyword fails. `tests/test_decode.py` runs the installed wheel over the demo capture and
`tests/files/iso2-tls.pcap` (a TLS 1.2 session and its key log). Captures are our own
software-in-the-loop recordings; do not add third-party captures.

Don't leave stale test agents or extensions running; never commit without an explicit ask.
