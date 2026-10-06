# V2G

> Decode ISO 15118 / DIN 70121 EV-charging communication (and any SocketCAN traffic in
> the same capture) into Zelos traces — from a packet capture or live off the wire.

A [Zelos](https://zeloscloud.io) agent extension. It turns the V2G conversation
between an electric vehicle (EVCC) and a charger (SECC) into plottable, queryable
signals and a searchable message timeline — the same data you would read in Wireshark
with the dsV2Gshark plugin, but as first-class Zelos traces you can plot, correlate
with other signals, query from the CLI, and share as a `.trz`.

It also decodes **CAN** frames captured alongside V2G (Wireshark/tcpdump on a SocketCAN
interface). A capture carrying **both** — e.g. a bench recording of a charging session
next to the vehicle bus — converts to **one time-aligned `.trz`**, CAN beside the V2G events
on the same clock, so you can correlate the CAN bus with the charging handshake.

## What it decodes

Decode is layered, so you get useful output even on captures the EXI codec can't fully
parse:

**Layer 1 — transport & pairing (always on, pure-Python):**
- **SLAC** HomePlug AV pairing handshake (ISO 15118-3) — every MME, in order, typed by
  its MMTYPE name (e.g. `CM_SLAC_PARM.REQ`, `CM_ATTEN_CHAR.IND`, `CM_SLAC_MATCH.CNF`)
  with source/destination MAC and the raw frame bytes retained per row. Frames that
  carry decodable fields are decoded per-frame: `CM_ATTEN_CHAR.IND` → the link
  attenuation profile (per-group dB), `CM_SLAC_MATCH.CNF` → the matched NID/NMK. SLAC
  bring-up is the most common field failure, so the full handshake is on the timeline.
- **SDP** SECC discovery — the resolved charger IP/port, security, and transport.
- **V2GTP** message timeline — every application message with direction, length, and
  raw EXI retained per row.

Every event corresponds to a frame on the wire and its decoded fields — the extension
does not synthesize cross-frame "session health" summaries or roll-ups.

**Layer 2 — application message field decode (via bundled libcbv2g):**
- **DIN 70121** and **ISO 15118-2** DC/AC sessions: each message type becomes its own
  event whose fields are the standard signals — SoC, target/present voltage & current,
  EVSE ratings, response codes, processing state, EVSE ID, and so on.
- **supportedAppProtocol (SAP)** handshake — the negotiated protocol and version, which
  also sets the session's dialect authoritatively.

Each decoded field carries its real unit (V, A, %, W, Wh) and enum value tables
(response codes, EVSE status), so plots and queries read in engineering terms.

**CAN (SocketCAN, in the same capture):**
- **Raw frames (always):** every SocketCAN frame, classic or CAN FD, becomes a `CAN/Frame`
  row — arbitration id, flags, dlc, and raw data bytes, as seen on the bus (the `candump`
  view). Error frames and malformed records are skipped and counted (`zelos.can.frame.v1`
  cannot mark an error frame).
- **Decoded signals (with a `.dbc`):** pass `--dbc vehicle.dbc` (repeatable, later files
  win) and matching frames also
  decode into named `CAN/<id>_<message>` signal events — with units, scaling, value
  tables, and multiplexing — using the shared Rust `zelos-can` codec.

> Not yet wired (the codec supports them; deferred until needed): ISO 15118-20, and
> TLS-encrypted / Plug & Charge certificate sessions. Captures using these still decode
> at Layer 1 and for any cleartext messages.

## Install

```bash
zelos extensions install-local /path/to/zelos-extension-v2g
```

No compiler is required — the EXI codec ships prebuilt and is loaded via stdlib `ctypes`
(see [Architecture](#architecture)). Live capture on Linux needs libpcap at runtime
(scapy compiles the capture filter with it; Debian/Ubuntu: `apt install libpcap0.8`).

## Usage

### Convert a capture (offline)

```bash
# V2G / CAN / both — auto-detected per frame
uv run python main.py convert session.pcapng -o session.trz

# decode CAN signals too (raw CAN frames are always kept). A ready-made combined
# CAN+V2G example ships in tests/files/ (see tests/files/README.md):
uv run python main.py convert tests/files/combined_can_v2g.pcapng \
  --dbc tests/files/example.dbc -o session.trz

# or the V2G/convert_pcap action (runs without the extension started)
```

Accepts `.pcap` and `.pcapng`. A capture with both CAN and V2G produces one time-aligned
trace. Open the resulting `.trz` in the Zelos app, or query it:

```bash
zelos trace signals session.trz                 # list decoded signals
zelos trace query  session.trz -s '*/V2G/session/current_demand_res.evse_present_voltage'
```

### Live capture

Add one `interfaces[]` entry per bridged green-PHY interface (Auto-configure fills in
every interface that is up), or set `advanced.replay_pcap` to stream a capture through
the live path without hardware. Decoded signals stream to the agent in real time:

```bash
zelos live events
zelos live query -s '*/V2G/eth0/current_demand_req.ev_target_current' --last 30s
```

Standalone (no agent config): `uv run python main.py live --iface eth0` or `--replay file.pcap`.

> Live capture needs raw-socket rights on the agent's machine. The
> `V2G/check_permissions` action opens a capture and, if refused, returns the fix
> (macOS: `/dev/bpf` access via ChmodBPF; Linux: `AmbientCapabilities=CAP_NET_RAW` on
> the agent's systemd unit, or root; or, broader, `setcap cap_net_raw=eip` on the
> interpreter, which covers every program it runs and is lost on its upgrade). An interface that fails to open is logged and
> skipped; the extension exits only if none opens. `V2G/check_permissions` also runs
> while the extension is stopped, so it works when a start failed.
>
> On Linux loopback (`lo`) each frame is seen twice by a raw socket (outgoing and
> incoming copy); like libpcap, the extension keeps one.

### Live from a remote bench (pipe / SSH)

The network analog of `candump | cantools decode`: pipe a capture tool's pcap stream
straight into `decode` over stdin — no files, decodes as it arrives. Ideal for a remote
charger/HIL where you can't run the agent:

```bash
ssh root@charger-bench \
  "tcpdump -i eth0 -U -s0 -w - 'ip6 or ether proto 0x88e1'" \
  | uv run python main.py decode
```

The signals appear live in the Zelos app exactly as on the bench. Notes:
- **Filter** must keep all three layers — `'ip6 or ether proto 0x88e1'` (SDP+V2GTP over
  IPv6, SLAC over HomePlug AV). Don't filter on `tcp` alone or you lose SLAC and SDP.
- **Interface**: `-i eth0` (Ethernet) and `-i any` (Linux cooked / SLL) both decode.
- `-U` (unbuffered) makes it stream in real time rather than in blocks.

## Configuration

| Field | Purpose |
|-------|---------|
| `interfaces[].interface` | Interface to capture (picked from `V2G/list_interfaces`). |
| `interfaces[].name` | Branch name (default: the interface, catalog-sanitized). Must be unique. |
| `advanced.prefix` | Shared source name (default `V2G`). Clear it for one source per branch. |
| `advanced.promiscuous` | Capture third-party unicast (default on; off for drivers that refuse it). |
| `advanced.log_packets` | Raw `zelos.packet.v1` rows at `<name>/packets` (default on; see below). |
| `advanced.log_frames` | Keep frame bytes in the packet rows (default on). |
| `advanced.stored_frame_bytes` | Cap on stored frame bytes (default null: every byte). |
| `advanced.replay_pcap` | Replay a capture instead of the interface list; branch = file stem. |
| `advanced.database_files` | CAN databases for SocketCAN frames in the replay file, in precedence order (later wins; empty: raw frames only). |
| `advanced.log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |

Packet rows cover each frame of a link type the packet decoder knows, except SocketCAN
frames (those are `CAN/Frame` rows). Live, that is only what the V2G capture filter passes
(IPv6 + HomePlug AV); for a full wire view, run the Packet extension on the same interface.

## Trace layout

One branch per interface (live) or per file (replay, convert), `<name>` below:

| Event | Contents |
|-------|----------|
| `<prefix>/<name>/slac`, `slac_attenuation`, `slac_match` | SLAC frames and their per-frame decode. |
| `<prefix>/<name>/sdp` | SDP discovery. |
| `<prefix>/<name>/message` | V2GTP message timeline, raw EXI per row. |
| `<prefix>/<name>/<message>` | Decoded fields, e.g. `pre_charge_res`, `current_demand_req`. |
| `<prefix>/<name>/packets` | Captured frames as `zelos.packet.v1` (the Packet panel; scope above). |
| `<prefix>/<name>/CAN/Frame` | SocketCAN frames in a converted, replayed or piped capture (`zelos.can.frame.v1`). |
| `<prefix>/<name>/CAN/<id>_<message>` | DBC-decoded CAN signals (`--dbc` / `advanced.database_files`). |

With the prefix cleared, `<name>` is the source and V2G events are unprefixed; the packet
and CAN events keep their `<name>/` segment (`<name>/<name>/packets`). Logs land at
`<prefix>/log` (`v2g_log/log` when cleared).

## Actions

| Action | Purpose |
|--------|---------|
| `V2G/auto_config` | Config with every up, non-loopback interface (standalone). |
| `V2G/list_interfaces` | Interface choices for the config form (standalone). |
| `V2G/convert_pcap` | Capture to `.trz`, optional DBCs and packet rows (standalone). |
| `V2G/check_permissions` | Try a capture; on refusal return the OS-specific fix (standalone). |

## Architecture

V2G application messages are **EXI** (schema-informed binary XML). Rather than
reimplement an EXI codec, the extension reuses EVerest's
[`libcbv2g`](https://github.com/EVerest/libcbv2g) (Apache-2.0) — the reference DIN /
ISO 15118 codec — through a thin C shim (`native/v2g_din_shim.c`) that decodes one
message to compact JSON. The shim is statically linked into a single self-contained
shared library, **prebuilt per platform and committed** under
`zelos_extension_v2g/exi/_lib/`. The Python side is pure (`ctypes` is stdlib), so
install needs no toolchain and publishes no wheels; if no artifact exists for the
running platform, decode degrades gracefully to Layer 1.

Capture parsing uses [scapy](https://scapy.net) (pcap + pcapng); V2GTP framing, TCP
reassembly, and SLAC body decode are pure-Python. The offline converter and the live
path share one codec, so they emit identical schemas.

CAN frames are decoded by the shared [`zelos-can`](https://pypi.org/project/zelos-can/)
codec (raw logging + DBC signal decode, in Rust) — the same engine as the standalone
Zelos CAN extension, so decoded signals are consistent across both. This extension only
adds the SocketCAN pcap parsing and routes frames to it.

To rebuild the native shim for a platform: `bash native/build.sh` (needs `cmake`, a C
compiler, and `git`). See [`native/README.md`](native/README.md).

## Changes

- **Unreleased:** events moved from `v2g/<event>` to `V2G/<name>/<event>` (one branch per
  interface or file); `--source-name` became `--prefix` (`advanced.prefix`); the CAN
  database setting is a list (`advanced.database_files`, `-d/--dbc` repeatable).

## Links

- [Repository](https://github.com/zeloscloud/zelos-extension-v2g)
- [Issues](https://github.com/zeloscloud/zelos-extension-v2g/issues)
- [Zelos Documentation](https://docs.zeloscloud.io)
- [SDK Guide](https://docs.zeloscloud.io/sdk)

## License

MIT License — see [LICENSE](LICENSE) for details. Bundles EVerest `libcbv2g`
(Apache-2.0).
