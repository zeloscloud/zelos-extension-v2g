# V2G

> Decode ISO 15118 / DIN 70121 EV-charging communication into Zelos traces — from a
> packet capture or live off the wire.

A [Zelos](https://zeloscloud.io) agent extension. It turns the V2G conversation
between an electric vehicle (EVCC) and a charger (SECC) into plottable, queryable
signals and a searchable message timeline — the same data you would read in Wireshark
with the dsV2Gshark plugin, but as first-class Zelos traces you can plot, correlate
with other signals, query from the CLI, and share as a `.trz`.

## What it decodes

Decode is layered, so you get useful output even on captures the EXI codec can't fully
parse:

**Layer 1 — transport & pairing (always on, pure-Python):**
- **SLAC** HomePlug AV pairing handshake (ISO 15118-3) — every MME, plus a one-row
  **init health summary** (matched?, duration, MNBC sound count, attenuation profile in
  dB, NID/NMK) and the 58-group attenuation profile. SLAC bring-up is the most common
  field failure, so this stands on its own.
- **SDP** SECC discovery — the resolved charger IP/port, security, and transport.
- **V2GTP** message timeline — every application message with direction, length, and
  raw EXI retained per row.

**Layer 2 — application message field decode (via bundled libcbv2g):**
- **DIN 70121** and **ISO 15118-2** DC/AC sessions: each message type becomes its own
  event whose fields are the standard signals — SoC, target/present voltage & current,
  EVSE ratings, response codes, processing state, EVSE ID, and so on.
- **supportedAppProtocol (SAP)** handshake — the negotiated protocol and version, which
  also sets the session's dialect authoritatively.

Each decoded field carries its real unit (V, A, %, W, Wh) and enum value tables
(response codes, EVSE status), so plots and queries read in engineering terms.

> Not yet wired (the codec supports them; deferred until needed): ISO 15118-20, and
> TLS-encrypted / Plug & Charge certificate sessions. Captures using these still decode
> at Layer 1 and for any cleartext messages.

## Install

```bash
zelos extensions install-local /path/to/zelos-extension-v2g
```

No compiler or extra system packages are required — the EXI codec ships prebuilt and is
loaded via stdlib `ctypes` (see [Architecture](#architecture)).

## Usage

### Convert a capture (offline)

```bash
# CLI
uv run python main.py convert session.pcap -o session.trz

# or as an agent action: "Convert Pcap"
```

Accepts `.pcap` and `.pcapng`. Open the resulting `.trz` in the Zelos app, or query it:

```bash
zelos trace signals session.trz                 # list decoded signals
zelos trace query  session.trz -s '*/v2g/current_demand_res.evse_present_voltage'
```

### Live capture

Configure the extension with an `interface` to sniff a bridged green-PHY link, or a
`replay_pcap` to stream a capture through the live path (handy for testing without
hardware). Decoded signals stream to the agent in real time:

```bash
zelos extensions start local.zelos-extension-v2g \
  --config '{"interface": "eth0", "source_name": "v2g"}'

zelos live signals
zelos live query -s '*/v2g/current_demand_req.ev_target_current' --last 30s
```

Standalone (no agent): `uv run python main.py live --iface eth0` or `--replay file.pcap`.

> Live capture needs raw-socket permission. On a permissioned Linux deploy `interface=`
> works directly; on macOS the agent runs non-root, so use `replay_pcap` there.

## Configuration

| Field         | Purpose                                                            |
|---------------|-------------------------------------------------------------------|
| `interface`   | Network interface(s) to sniff live (comma-separated for several). |
| `replay_pcap` | A pcap/pcapng to replay through the live path instead of sniffing.|
| `source_name` | Trace source name (default `v2g`).                                |
| `log_level`   | `DEBUG` / `INFO` / `WARNING` / `ERROR`.                           |

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

To rebuild the native shim for a platform: `bash native/build.sh` (needs `cmake`, a C
compiler, and `git`). See [`native/README.md`](native/README.md).

## Links

- [Repository](https://github.com/zeloscloud/v2g)
- [Issues](https://github.com/zeloscloud/v2g/issues)
- [Zelos Documentation](https://docs.zeloscloud.io)
- [SDK Guide](https://docs.zeloscloud.io/sdk)

## License

MIT License — see [LICENSE](LICENSE) for details. Bundles EVerest `libcbv2g`
(Apache-2.0).
