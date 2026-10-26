# CLAUDE.md — zelos-extension-v2g

Decodes ISO 15118 / DIN 70121 V2G (EV ↔ charger) traffic into Zelos traces — from a pcap or
live off the wire. Also decodes SocketCAN frames found in the same capture, so a capture with
both CAN and V2G converts to one time-aligned `.trz`.

## Layout

| Path | Role |
|------|------|
| `protocol.py` | Wire constants + SLAC MMTYPE table. |
| `pcap.py` | SLAC/SDP/V2GTP record types and per-frame parsers; `link_frame` (Ethernet + Linux cooked SLL). |
| `stream.py` | Incremental V2GTP framer every ingest path feeds (`V2gStreamDecoder`). |
| `slac.py` | Per-frame SLAC field decode (attenuation, match). |
| `codec.py` | V2G records → trace events; `emit_message` dispatches DIN/ISO-2/SAP. |
| `socketcan.py` | Parse `LINKTYPE_CAN_SOCKETCAN` (227) records → `CanFrame`. |
| `can_ingest.py` | Glue to `zelos_can.CanDecoder` (raw + DBC decode lives in `zelos-can`). |
| `converter.py` | `convert_capture(in, out, dbc=)` — any capture → `.trz`. |
| `live.py` | `sniff_into` (iface/replay) + `decode_stream_into` (stdin pcap). |
| `extension.py` | `V2gConverter`: the Convert Pcap and Get Status actions. |
| `cli/` | `app.py` (agent app-mode), `convert.py`, `live.py`, `decode.py`. |
| `exi/libv2g.py`, `exi/_lib/` | ctypes binding + prebuilt libcbv2g shim (one per platform). |
| `native/` | The C shim (`v2g_din_shim.c`) + build scripts. |

## Design principle

**Packet-in / row-out:** every event maps to one frame on the wire and its decoded fields.
Decode encoded bytes into human-readable fields wherever possible, but **synthesize nothing
across frames** — no session summaries, health roll-ups, or inferred/default values.

## Decode is layered

- **Layer 1** (pure-Python, always): SLAC handshake (per MMTYPE, raw bytes retained;
  `CM_ATTEN_CHAR.IND` / `CM_SLAC_MATCH.CNF` also decoded per-frame), SDP discovery, and the
  V2GTP message timeline with raw EXI per row.
- **Layer 2** (needs the bundled shim): per-message EXI field decode. If no shim exists for
  the platform, `libv2g.available()` is False and Layer 1 stands alone.

All ingest paths share one decode: offline `convert_capture`, live iface/replay (`sniff_into`),
and stdin (`decode_stream_into` / the `decode` subcommand — `tcpdump -w - | … decode`).
`link_frame` makes it link-layer-agnostic (Ethernet + Linux cooked SLL), so `-i eth0` and
`-i any` both decode.

`emit_message` tries `decode_din → decode_iso2 → decode_sap`; the dialects are mutually
exclusive, and DIN / ISO 15118-2 share field names so the codec events are reused across both.

## Bundled EXI codec

V2G messages are EXI, decoded via EVerest `libcbv2g` (Apache-2.0) through a C shim, statically
linked into one shared lib **prebuilt per platform and committed** under
`exi/_lib/libv2gshim-<os>-<arch>.{dylib,so}`, loaded via stdlib `ctypes`. **No compiler runs at
install; nothing is published to PyPI** — keep it that way.

- **Shim ↔ codec contract:** every field the shim emits must appear in `codec._FIELD_META`
  (field → DataType + unit) or it is silently dropped. Widen both together.
- **Rebuild:** `bash native/build.sh` (needs `cmake`, a C compiler, `git`; position-independent
  code is required on x86_64). `bash native/build-linux.sh` cross-builds the Linux `.so`s in
  manylinux containers. Commit the rebuilt artifacts.

## CAN-in-pcap

`convert_capture` reads a capture once and dispatches per frame: no `link_frame` → SocketCAN →
`zelos_can.CanDecoder`; Ethernet/IPv6/HomePlug-AV → `V2gStreamDecoder`. Both write **one shared
`TraceNamespace`**, so CAN (`can_raw/*`, plus decoded `can_codec/<id>_<msg>` with a DBC) and V2G
(`v2g/*`) land in one time-aligned `.trz`. CAN-only, V2G-only, and combined captures all fall
out of the same pass.

**CAN decode is not reimplemented here** — raw + DBC frame cracking lives in the `zelos-can`
dependency; `can_ingest.py` is only glue, and `socketcan.py` hand-parses the 16-byte classic
frame (id/flags big-endian: bit31 EFF / bit30 RTR / bit29 ERR; byte 4 = dlc ≤ 8) because scapy
has no linktype-227 dissector. Two `CanDecoder` gotchas:

1. The DBC is optional (`zelos-can >= 0.0.7a0`); pass `log_raw_frames=True` so raw frames are
   kept even when a DBC is decoding signals.
2. Bind it to the writer's namespace via injected `source=` / `raw_source=` `TraceSource`s —
   `source_name=` alone binds the default namespace and the trace comes out empty.

## Trace output

The offline converter uses an isolated `TraceNamespace` + `TraceWriter` (no agent), and relies
on `TraceWriter.close()` to flush buffered events. Converted rows keep the original capture
timestamps; the replay path re-stamps to arrival time (like `tcpreplay`).

## Testing

```bash
just check    # ruff format check and lint
just format   # ruff format
just test     # pytest — runs against the committed pyPLC fixtures in tests/files/
just package  # zelos extensions package .
```

Layer-2 tests are `skipif(not libv2g.available())`. Don't leave stale test agents/extensions
running; never commit without an explicit ask.
