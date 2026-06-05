# CLAUDE.md — zelos-extension-v2g

Decodes ISO 15118 / DIN 70121 V2G (EV ↔ charger) communication into Zelos traces, from
a pcap or live off the wire. Converter-first; live capture shares the same codec.

## Layout

| Path | Role |
|------|------|
| `zelos_extension_v2g/protocol.py` | Wire constants + SLAC MMTYPE table (no logic). |
| `zelos_extension_v2g/pcap.py` | scapy-based offline reader → SLAC/SDP/V2GTP records (`decode_session`). |
| `zelos_extension_v2g/stream.py` | Incremental V2GTP framer for the live path (`V2gStreamDecoder`). |
| `zelos_extension_v2g/slac.py` | Pure-Python SLAC body decode + init health summary. |
| `zelos_extension_v2g/exi/libv2g.py` | ctypes binding to the bundled libcbv2g shim. |
| `zelos_extension_v2g/exi/_lib/` | Prebuilt, committed shim libraries (one per platform). |
| `zelos_extension_v2g/codec.py` | Records → Zelos trace events (the shared schema). |
| `zelos_extension_v2g/converter.py` | `convert_v2g_pcap(in, out)` — pcap → `.trz`. |
| `zelos_extension_v2g/live.py` | `sniff_into` / `run_live` — scapy sniff/replay → live source. |
| `zelos_extension_v2g/cli/` | `app.py` (agent app-mode), `live.py` (standalone live CLI). |
| `native/v2g_din_shim.c` + `build.sh` | The C shim and its build script. |

## Decode is layered

- **Layer 1** (pure-Python, always works): SLAC handshake + init summary, SDP discovery,
  V2GTP message timeline with raw EXI retained per row.
- **Layer 2** (needs the bundled shim): per-message EXI field decode. If no shim is
  bundled for the platform, `libv2g.available()` is False and Layer 1 stands alone.

`codec.emit_message` dispatches per dialect: `decode_din(exi) or decode_iso2(exi) or
decode_sap(exi)`. The dialects are mutually exclusive — a message of one dialect returns
`None` from the others' decoders — so order is safe. DIN and ISO 15118-2 share field
names, so the same codec events are reused across both.

## The bundled native codec

V2G messages are EXI; we decode them with EVerest's `libcbv2g` (Apache-2.0) via a C shim,
**not** a Python reimplementation (a pure-Python EXI decode was attempted and abandoned —
the per-field grammar is error-prone). The shim is statically linked into one shared lib,
prebuilt per platform and committed under `exi/_lib/libv2gshim-<os>-<arch>.{dylib,so}`, and
loaded with stdlib `ctypes`. **No compiler runs at install time and nothing is published to
PyPI** — this is the whole point; keep it that way (pure-Python deps only; no target-side
build step).

**Shim ↔ codec contract:** every field the shim emits in its JSON must appear in
`codec._FIELD_META` (field → DataType + unit) or it is silently dropped. When you widen the
shim to emit a new field, add it there too.

**Rebuilding after editing the shim:** `bash native/build.sh` (needs `cmake`, a C compiler,
`git`; `LIBCBV2G_REF=<tag>` to pin) builds for the current platform. It links `din.a` +
`iso2.a` + `exi_codec.a` — `din.a` also carries the appHand/SAP decoder — with
`-DCMAKE_POSITION_INDEPENDENT_CODE=ON` (required on x86_64). To produce both Linux `.so`s
from a macOS/Docker host, `bash native/build-linux.sh` runs it inside manylinux2014
containers. Commit the rebuilt artifacts. Currently committed: `darwin-arm64.dylib`,
`linux-x86_64.so`, `linux-arm64.so` (glibc-2.17 baseline).

## SDK init ordering (don't break this)

In app-mode (`cli/app.py`) the live `V2gCodec` (its `TraceSource`) is created **before**
`zelos_sdk.init()`, and any actions are registered before init too — anything registered
after init is invisible to the agent. The offline converter instead uses an isolated
`TraceNamespace` + `TraceWriter` (no agent involved).

The converter keeps original pcap timestamps; the **replay** live path re-stamps records to
arrival time so a replayed capture lands in the live window (mirrors `tcpreplay` on a wire).

## Testing

`uv run pytest -q` — the suite runs against the real DIN fixture
`tests/files/v2g_din_session.pcap` (a real DC session stuck in CableCheck, so it exercises
SLAC/SDP/SAP/framing + SoC telemetry). ISO 15118-2 decode is covered by
`test_iso2_exi_decode`, which embeds two real ISO-2 EXI vectors inline (no second large
fixture). Layer-2 tests are `skipif(not libv2g.available())` so they're skipped cleanly on a
platform with no bundled shim.

```bash
just check      # ruff lint
just format     # ruff format
just test       # pytest
just package    # zelos extensions package .
```

Always kill any test agent/extension you start — do not leave stale processes running.
Never commit without an explicit ask.
