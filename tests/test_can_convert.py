"""Tests for SocketCAN-in-pcap decode and the combined CAN+V2G convert.

The CAN fixture is generated in-process (a standard classic-pcap SocketCAN
capture), so no external/private capture is committed. DBC decode is exercised
with a tiny inline database. CAN frame cracking itself lives in the shared
``zelos-can`` package; these tests cover our pcap ingest, dispatch, and the
shared-namespace combined writer.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
import zelos_sdk

from zelos_extension_v2g.can_ingest import CanIngest
from zelos_extension_v2g.codec import V2gCodec
from zelos_extension_v2g.converter import convert_capture
from zelos_extension_v2g.pcap import SlacFrame
from zelos_extension_v2g.socketcan import parse_socketcan

FILES = Path(__file__).parent / "files"
V2G_FIXTURE = FILES / "2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng"

_MINI_DBC = 'VERSION ""\n\nBS_:\n\nBU_: ECU\n\nBO_ 320 Msg320: 2 ECU\n SG_ Speed : 0|16@1+ (0.1,0) [0|6553.5] "km/h" ECU\n'  # noqa: E501

# (ts, can_id, extended, dlc, data)
_FRAMES = [
    (1000.00, 0x140, False, 2, b"\x64\x00"),  # Msg320 Speed = 10.0 km/h
    (1000.10, 0x140, False, 2, b"\xc8\x00"),  # Msg320 Speed = 20.0 km/h
    (1000.20, 0x7FF, False, 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),  # unknown id
    (1000.30, 0x12345678, True, 4, b"\xde\xad\xbe\xef"),  # extended, unknown
]


def _socketcan_record(can_id: int, extended: bool, dlc: int, data: bytes) -> bytes:
    """A 16-byte classic SocketCAN record (big-endian id/flags word)."""
    idfield = can_id | (0x80000000 if extended else 0)
    return struct.pack(">I", idfield) + bytes([dlc & 0xFF, 0, 0, 0]) + data.ljust(8, b"\x00")


def _write_socketcan_pcap(path: Path, frames) -> None:
    """Write a classic pcap (LINKTYPE_CAN_SOCKETCAN = 227) of the given frames."""
    with path.open("wb") as f:
        # global header: magic, v2.4, thiszone, sigfigs, snaplen, network=227
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 227))
        for ts, cid, ext, dlc, data in frames:
            rec = _socketcan_record(cid, ext, dlc, data)
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(rec), len(rec)) + rec)


@pytest.fixture
def can_pcap(tmp_path: Path) -> Path:
    p = tmp_path / "canbus.pcap"
    _write_socketcan_pcap(p, _FRAMES)
    return p


def _field_paths(trz: Path) -> set[str]:
    reader = zelos_sdk.TraceReader(str(trz))
    reader.open()
    try:
        return {f.path for src in reader.list_fields() for ev in src.events for f in ev.fields}
    finally:
        reader.close()


def _sources(paths: set[str]) -> set[str]:
    """The source segment of each field path (``*/<source>/<event>.<field>``)."""
    return {p.split("/")[1] for p in paths if "/" in p}


def test_parse_socketcan_standard_and_extended() -> None:
    f = parse_socketcan(1.0, _socketcan_record(0x140, False, 2, b"\x64\x00"))
    assert f is not None
    assert (f.can_id, f.extended, f.remote, f.dlc, f.data) == (0x140, False, False, 2, b"\x64\x00")

    g = parse_socketcan(2.0, _socketcan_record(0x12345678, True, 4, b"\xde\xad\xbe\xef"))
    assert g is not None
    assert (g.can_id, g.extended, g.dlc, g.data) == (0x12345678, True, 4, b"\xde\xad\xbe\xef")


def test_parse_socketcan_rejects_malformed() -> None:
    assert parse_socketcan(0.0, b"\x00" * 15) is None  # wrong length
    assert parse_socketcan(0.0, _socketcan_record(0x1, False, 9, b"")) is None  # dlc > 8


def test_convert_can_only_raw_frames(can_pcap: Path, tmp_path: Path) -> None:
    stats = convert_capture(can_pcap, tmp_path / "can.trz")
    assert stats.can_frames == 4
    assert stats.can_decoded_frames == 0  # no DBC => raw frames only
    assert stats.v2g.messages == 0
    assert any(s.startswith("can") for s in _sources(_field_paths(tmp_path / "can.trz")))


def test_convert_can_with_dbc(can_pcap: Path, tmp_path: Path) -> None:
    dbc = tmp_path / "mini.dbc"
    dbc.write_text(_MINI_DBC)
    out = tmp_path / "can_dbc.trz"
    stats = convert_capture(can_pcap, out, dbc=dbc)
    assert stats.can_frames == 4
    assert stats.can_decoded_frames == 2  # the two 0x140 frames match Msg320
    assert any(p.endswith(".Speed") for p in _field_paths(out)), "decoded Speed signal missing"


def test_v2g_only_has_no_can_tables(tmp_path: Path) -> None:
    out = tmp_path / "v2g.trz"
    stats = convert_capture(V2G_FIXTURE, out)
    assert stats.can_frames == 0
    sources = _sources(_field_paths(out))
    assert "v2g" in sources
    assert not any(s.startswith("can") for s in sources), "no can* tables for a V2G-only capture"


def test_combined_shares_one_writer(tmp_path: Path) -> None:
    """CAN and V2G rows land in one trace via a shared namespace — the essential
    guarantee behind the combined convert (proven on real combined captures too)."""
    out = tmp_path / "combined.trz"
    ns = zelos_sdk.TraceNamespace("converter")
    with zelos_sdk.TraceWriter(str(out), namespace=ns):
        v2g = V2gCodec(namespace=ns)
        can = CanIngest(ns)
        v2g.emit_slac(
            SlacFrame(ts=1.0, mmtype=0x6064, name="CM_SLAC_PARM.REQ", src_mac="a", dst_mac="b")
        )
        can.emit(parse_socketcan(1.0, _socketcan_record(0x140, False, 2, b"\x64\x00")))

    sources = _sources(_field_paths(out))
    assert "v2g" in sources
    assert any(s.startswith("can") for s in sources)


# ─── combined CAN+V2G end-to-end (generate a 2-interface pcapng, query both) ──


def _pcapng_shb() -> bytes:
    body = struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    total = 12 + len(body)
    return struct.pack("<II", 0x0A0D0D0A, total) + body + struct.pack("<I", total)


def _pcapng_idb(linktype: int) -> bytes:
    body = struct.pack("<HHI", linktype, 0, 0)  # linktype, reserved, snaplen(0 = unlimited)
    total = 12 + len(body)
    return struct.pack("<II", 0x00000001, total) + body + struct.pack("<I", total)


def _pcapng_epb(iface_id: int, ts: float, data: bytes) -> bytes:
    ts_us = int(round(ts * 1_000_000))
    hi, lo = (ts_us >> 32) & 0xFFFFFFFF, ts_us & 0xFFFFFFFF
    pad = (-len(data)) % 4
    body = struct.pack("<IIIII", iface_id, hi, lo, len(data), len(data)) + data + b"\x00" * pad
    total = 12 + len(body)
    return struct.pack("<II", 0x00000006, total) + body + struct.pack("<I", total)


def _write_combined_pcapng(path: Path, v2g_src: Path, can_specs) -> None:
    """Write a 2-interface pcapng: iface 0 = SocketCAN (227), iface 1 = Ethernet (1).

    V2G Ethernet frames are copied verbatim from ``v2g_src`` (a real V2G capture);
    ``can_specs`` = list of ``(id, extended, dlc, data)`` spread across the V2G span,
    so CAN and V2G share one timeline — exactly the customer's combined capture.
    """
    from scapy.utils import PcapReader

    with PcapReader(str(v2g_src)) as reader:
        v2g = [(float(p.time), bytes(p)) for p in reader]
    ts_min = min(t for t, _ in v2g)
    ts_max = max(t for t, _ in v2g)
    events = [(t, 1, d) for t, d in v2g]
    for i, (cid, ext, dlc, data) in enumerate(can_specs):
        ts = ts_min + (ts_max - ts_min) * (i + 1) / (len(can_specs) + 1)
        events.append((ts, 0, _socketcan_record(cid, ext, dlc, data)))
    events.sort(key=lambda e: e[0])

    with path.open("wb") as f:
        f.write(_pcapng_shb())
        f.write(_pcapng_idb(227))  # iface 0 — SocketCAN
        f.write(_pcapng_idb(1))  # iface 1 — Ethernet
        for ts, iface, data in events:
            f.write(_pcapng_epb(iface, ts, data))


def _query_values(trz: Path, suffixes: list[str]) -> dict[str, list]:
    """Query raw (unsampled) values for fields (matched by path suffix) from a trace,
    the same read path the app/agent uses (``TraceReader.query`` → Arrow)."""
    pa = pytest.importorskip("pyarrow")
    reader = zelos_sdk.TraceReader(str(trz))
    reader.open()
    try:
        all_fields = [
            f.path for src in reader.list_fields() for ev in src.events for f in ev.fields
        ]
        fields = [next(p for p in all_fields if p.endswith(suf)) for suf in suffixes]
        segs = [s.id for s in reader.list_data_segments()]
        tr = reader.time_range()
        res = reader.query(data_segment_ids=segs, fields=fields, start=tr.start, end=tr.end)
        table = pa.ipc.open_stream(res.to_arrow()).read_all().to_pydict()
        out: dict[str, list] = {}
        for suf in suffixes:
            col = next(c for c in table if c.endswith(suf))
            out[suf] = [v for v in table[col] if v is not None]
        return out
    finally:
        reader.close()


def test_combined_capture_queries_both_families(tmp_path: Path) -> None:
    """E2E: a capture with BOTH CAN and V2G converts to one trace, and real CAN
    and V2G values are queryable *simultaneously* from it, on one timeline."""
    pytest.importorskip("pyarrow")
    combined = tmp_path / "combined.pcapng"
    # five 0x140 frames (Speed = 10.0 km/h under mini.dbc) + two unknown-id frames
    can_specs = [(0x140, False, 2, b"\x64\x00")] * 5 + [(0x200, False, 1, b"\x01")] * 2
    _write_combined_pcapng(combined, V2G_FIXTURE, can_specs)
    dbc = tmp_path / "mini.dbc"
    dbc.write_text(_MINI_DBC)

    out = tmp_path / "combined.trz"
    stats = convert_capture(combined, out, dbc=dbc)

    # both protocols decoded from the one capture
    assert stats.v2g.messages == 274
    assert stats.v2g.protocol == "DIN 70121"
    assert stats.can_frames == 7
    assert stats.can_decoded_frames == 5  # the five 0x140 frames match Msg320

    # both queryable by value from the one trace, on the shared clock
    vals = _query_values(
        out,
        ["v2g/cable_check_req.soc", "can_raw/can_raw.arbitration_id", "can/0140_Msg320.Speed"],
    )
    assert vals["v2g/cable_check_req.soc"], "no V2G SoC values queried back"
    assert 0x140 in vals["can_raw/can_raw.arbitration_id"], "CAN frame id 0x140 not in trace"
    assert 10.0 in [round(v, 1) for v in vals["can/0140_Msg320.Speed"]], "decoded CAN Speed missing"
