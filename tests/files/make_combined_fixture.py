#!/usr/bin/env python3
"""Regenerate ``combined_can_v2g.pcapng`` — a two-interface capture carrying BOTH
CAN and V2G, for exercising the combined CAN+V2G convert end-to-end.

Provenance (no customer data):

- **V2G** frames are copied verbatim from the public pyPLC Tesla Model Y capture
  (``2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng``) — a real DIN 70121 DC
  session.
- **CAN** frames are **synthetic**, carrying known values decodable by
  ``example.dbc``:
    - ``BMS_Status`` (0x100): PackVoltage 400.0 V, PackCurrent -50.0 A, SoC 55 %,
      ChargeState = Charging (and a second frame at 400.4 V / 56 %).
    - ``VCU_ChargeCommand`` (0x200): TargetVoltage 420.0 V, TargetCurrent 125.0 A.
    - one unknown id (0x7FF) that stays raw-only (no DBC entry).

The pcapng has interface 0 = SocketCAN (linktype 227) and interface 1 = Ethernet
(linktype 1); CAN frames are spread across the V2G time span so both share one
timeline. Run from the repo root:

    uv run python tests/files/make_combined_fixture.py
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.utils import PcapReader

HERE = Path(__file__).parent
V2G_SRC = HERE / "2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng"
OUT = HERE / "combined_can_v2g.pcapng"

# (arbitration_id, extended, dlc, data) — data little-endian per example.dbc.
CAN_FRAMES = [
    (0x100, False, 8, bytes.fromhex("A00F0CFE6E020000")),  # BMS_Status 400.0V -50.0A 55% Charging
    (0x200, False, 4, bytes.fromhex("6810E204")),  # VCU_ChargeCommand 420.0V 125.0A
    (0x100, False, 8, bytes.fromhex("A40F0CFE70020000")),  # BMS_Status 400.4V -50.0A 56% Charging
    (0x7FF, False, 3, bytes.fromhex("DEADBE")),  # unknown id -> raw only
]


def _socketcan_record(can_id: int, extended: bool, dlc: int, data: bytes) -> bytes:
    idfield = can_id | (0x80000000 if extended else 0)
    return struct.pack(">I", idfield) + bytes([dlc & 0xFF, 0, 0, 0]) + data.ljust(8, b"\x00")


def _block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _shb() -> bytes:
    return _block(0x0A0D0D0A, struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HHq", 1, 0, -1))


def _idb(linktype: int) -> bytes:
    return _block(0x00000001, struct.pack("<HHI", linktype, 0, 0))


def _epb(iface_id: int, ts: float, data: bytes) -> bytes:
    us = int(round(ts * 1_000_000))
    hi, lo = (us >> 32) & 0xFFFFFFFF, us & 0xFFFFFFFF
    pad = (-len(data)) % 4
    body = struct.pack("<IIIII", iface_id, hi, lo, len(data), len(data)) + data + b"\x00" * pad
    return _block(0x00000006, body)


def main() -> None:
    with PcapReader(str(V2G_SRC)) as reader:
        v2g = [(float(p.time), bytes(p)) for p in reader]
    ts_min = min(t for t, _ in v2g)
    ts_max = max(t for t, _ in v2g)
    events = [(t, 1, d) for t, d in v2g]
    for i, (cid, ext, dlc, data) in enumerate(CAN_FRAMES):
        ts = ts_min + (ts_max - ts_min) * (i + 1) / (len(CAN_FRAMES) + 1)
        events.append((ts, 0, _socketcan_record(cid, ext, dlc, data)))
    events.sort(key=lambda e: e[0])

    with OUT.open("wb") as f:
        f.write(_shb())
        f.write(_idb(227))  # interface 0 — SocketCAN
        f.write(_idb(1))  # interface 1 — Ethernet
        for _ts, iface, data in events:
            f.write(_epb(iface, _ts, data))

    print(
        f"wrote {OUT.name}: {OUT.stat().st_size} bytes, "
        f"{len(v2g)} V2G + {len(CAN_FRAMES)} CAN frames"
    )


if __name__ == "__main__":
    main()
