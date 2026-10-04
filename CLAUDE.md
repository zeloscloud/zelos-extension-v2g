# CLAUDE.md — zelos-extension-v2g

Decodes ISO 15118 / DIN 70121 V2G (EV ↔ charger) traffic into Zelos traces — from a pcap or
live off the wire. Also decodes SocketCAN frames found in the same capture, so a capture with
both CAN and V2G converts to one time-aligned `.trz`.

## Layout

| Path | Role |
|------|------|
| `protocol.py` | Wire constants + SLAC MMTYPE table. |
| `pcap.py` | SLAC/SDP/V2GTP record types + per-frame parse helpers; `link_frame` (Ethernet + Linux cooked SLL). |
| `stream.py` | `V2gStreamDecoder`: incremental TCP reassembly + V2GTP framing, the one decode path. |
| `slac.py` | Per-frame SLAC field decode (attenuation, match). |
| `codec.py` | `V2gCodec`: one branch; `feed(pkt)` → packet row + V2G events; `trace_layout`; `_MSG_FIELDS`. |
| `config.py` | Config parsing (`interfaces[]`, `advanced`), `branch_name`, `database_files`, `make_codec`. |
| `actions.py` | `V2G/` actions, all standalone: `auto_config`, `list_interfaces`, `convert_pcap`, `check_permissions`. |
| `socketcan.py` | Parse `LINKTYPE_CAN_SOCKETCAN` (227) records (classic 16 B, FD 72 B) → `CanFrame`. |
| `can_ingest.py` | Glue to `zelos_can.CanDecoder` (raw + DBC decode lives in `zelos-can`). |
| `converter.py` | `convert_capture(in, out, dbcs, prefix=, log_packets=)` — any capture → `.trz`. |
| `live.py` | `sniff_into` (one `AsyncSniffer` per interface; failures skipped), `replay_into`, `decode_stream_into`, `flush_every`. |
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

All ingest paths share one decode, `V2gCodec.feed(pkt)`: offline `convert_capture`, live
(`sniff_into`), replay (`replay_into`), and stdin (`decode_stream_into` / the `decode`
subcommand — `tcpdump -w - | … decode`). Replay/stdin re-stamp `pkt.time` before the feed, so
V2G events and packet rows share one timestamp: `int(pkt.time * 10**9)` on scapy's Decimal,
exact to the ns, for V2G, packet and CAN rows alike.

`feed` never raises: a frame that fails is logged once per exception type (with its frame
number) and counted in `frame_errors` (logged at stop, in convert stats). Without that guard,
an exception inside scapy's `sniff(prn=...)` closes the socket and that capture silently dies.
Shutdown order matters: stop sniffers / join workers, then the final flush (`flush_every`).
On Linux loopback, `open_capture` uses `L2socket`, which drops the `PACKET_OUTGOING` copy
(`L2listen` keeps both, so `lo` would double every row); real NICs keep outgoing frames.
`link_frame` makes it link-layer-agnostic (Ethernet + Linux cooked SLL), so `-i eth0` and
`-i any` both decode.

`emit_message` tries `decode_din → decode_iso2 → decode_sap`; the dialects are mutually
exclusive, and DIN / ISO 15118-2 share field names so the codec events are reused across both.

## Bundled EXI codec

V2G messages are EXI, decoded via EVerest `libcbv2g` (Apache-2.0) through a C shim, statically
linked into one shared lib **prebuilt per platform and committed** under
`exi/_lib/libv2gshim-<os>-<arch>.{dylib,so}`, loaded via stdlib `ctypes`. **No compiler runs at
install; nothing is published to PyPI** — keep it that way.

- **Shim ↔ codec contract:** every field the shim can emit for a message must be listed under
  it in `codec._MSG_FIELDS` (the event schema is registered whole, since optional fields are
  emitted only when present) and typed in `_FIELD_META` (XSD widths), or it is dropped.
  `test_msg_fields_cover_shim` diffs the table against the C source.
- **Rebuild:** `bash native/build.sh` (needs `cmake`, a C compiler, `git`; position-independent
  code is required on x86_64). `bash native/build-linux.sh` cross-builds the Linux `.so`s in
  manylinux containers. Commit the rebuilt artifacts. `LIBCBV2G_REF` pins the libcbv2g commit
  (v0.3.2); `exi/_lib/LICENSE-libcbv2g` ships its Apache-2.0 licence, keep its version in step.

## Trace layout

One `V2gCodec` per branch: an interface (live) or a file stem (replay, convert). `trace_layout`
is the one naming rule: with `advanced.prefix` (default `V2G`) every branch shares ONE source
object named after it and nests under `<name>/`; cleared, each branch owns a source `<name>`
with unprefixed events. Pass the shared source in (`make_codec(source=)`): two same-named
sources register separately and the query layer keeps only the newest.

Each codec also owns a `zelos_packet.PacketDecoder` (`advanced.log_packets`) on the same source,
so rows land at `<name>/packets` (`zelos.packet.v1`; with the prefix cleared that is
`<name>/<name>/packets`). `decode_frame` buffers with no timer: live paths flush every 0.5 s
(`flush_every`), converts flush before the writer closes. Never `convert_file` for a convert: it
pushes a stats row stamped wall-clock now, stretching the trace's time range to today.

## CAN-in-pcap

`convert_capture` reads a capture once and dispatches per frame on the link type: DLT 227
records (scapy's `CAN` / `CANFD`, registered by importing `scapy.layers.can`) →
`zelos_can.CanDecoder`; anything else → the file's `V2gCodec`. The CAN decoder writes into that
codec's source, under `<name>/CAN/Frame` (raw, `zelos.can.frame.v1`) and `<name>/CAN/<id>_<msg>`
(with a DBC), so a combined capture is one time-aligned branch. It is created on the first
SocketCAN frame, so V2G-only captures get no CAN tables. The split lives in `V2gCodec.feed`
(`make_codec(can=True)`), shared by convert, replay and stdin; live sniffs leave it off.
Each convert uses a fresh `TraceNamespace`, so repeated action runs leak no schemas.

**CAN decode is not reimplemented here** — raw + DBC frame cracking lives in the `zelos-can`
dependency; `can_ingest.py` is only glue, and `socketcan.py` hand-parses the record bytes
(id/flags big-endian: bit31 EFF / bit30 RTR / bit29 ERR; byte 4 = length; 16 B classic, 72 B
FD → `is_fd=True`) rather than scapy's CAN fields, whose byte order is a global scapy setting. Error
frames are skipped and counted (`zelos.can.frame.v1` has no error flag), as are malformed
records. DBCs are a list (`advanced.database_files`, `-d` repeatable), later wins, like the CAN
extension. Two `CanDecoder` gotchas:

1. The DBC is optional; pass `log_raw_frames=True` so raw frames are kept even when a DBC is
   decoding signals.
2. Bind it via injected `source=` / `raw_source=` — `source_name=` alone binds the default
   namespace and the trace comes out empty.

## SDK init ordering

In app-mode (`cli/app.py`), before `zelos_sdk.init(name="V2G", actions=True)`: register the
actions (init advertises them) and create the shared source with `init_global_source(prefix or
"v2g_log")`, so init reuses it rather than making a second one; logs go there as `log`.
`ACTION_PREFIX` lives in the package and `main.py` re-exports it for the at-rest action dump
(`just package` generates `actions.json`). The converter uses its own `TraceNamespace` +
`TraceWriter` (no agent); converted rows keep the capture timestamps, replay re-stamps to now.

## Testing

```bash
just check    # ruff lint
just format   # ruff format
just test     # pytest — runs against the committed pyPLC fixtures in tests/files/
just package  # zelos extensions package . (also generates actions.json)
```

Layer-2 tests are `skipif(not libv2g.available())`. Don't leave stale test agents/extensions
running; never commit without an explicit ask.
