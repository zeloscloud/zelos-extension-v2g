"""Per-branch trace layout: live routing by interface, and convert's packet rows."""

from __future__ import annotations

from pathlib import Path

import pytest
import zelos_sdk
from scapy.utils import PcapReader

from zelos_extension_v2g.config import (
    ConfigError,
    PacketOptions,
    make_codec,
    parse_interfaces,
)
from zelos_extension_v2g.converter import convert_capture

FILES = Path(__file__).parent / "files"
FIXTURE = FILES / "2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng"
SLAC_FAIL = FILES / "2023-05-03_TaycanLeftside_slacFail.pcapng"


def _events(trz: Path) -> dict[str, str]:
    """Event path -> event type."""
    reader = zelos_sdk.TraceReader(str(trz))
    reader.open()
    try:
        return {ev.path: ev.event_type for src in reader.list_fields() for ev in src.events}
    finally:
        reader.close()


def _ns(iso: str) -> int:
    """``2024-04-20T15:02:03.276540928+00:00`` -> epoch ns."""
    from datetime import datetime

    whole, frac = iso.removesuffix("+00:00").split(".")
    return int(datetime.fromisoformat(whole + "+00:00").timestamp()) * 10**9 + int(
        frac.ljust(9, "0")
    )


def test_interfaces_route_to_their_own_branch(tmp_path: Path, monkeypatch) -> None:
    config = {"interfaces": [{"interface": "en0"}, {"interface": "eth0.1"}, {"interface": "bad0"}]}
    branches = parse_interfaces(config, "V2G")
    assert [b.name for b in branches] == ["en0", "eth0_1", "bad0"]
    with pytest.raises(ConfigError, match="Duplicate name 'eth0_1'"):
        parse_interfaces({"interfaces": [*config["interfaces"], {"interface": "eth0_1"}]}, "V2G")

    import threading

    import scapy.sendrecv

    from zelos_extension_v2g import live

    captures = {"en0": FIXTURE, "eth0.1": SLAC_FAIL}

    def fake_open(iface, promisc):
        if iface not in captures:
            raise OSError(f"Cannot set promiscuous mode on interface ({iface})!")
        return captures[iface]

    def fake_sniff(opened_socket, prn, **_):
        with PcapReader(str(opened_socket)) as reader:
            for pkt in reader:
                prn(pkt)

    monkeypatch.setattr(live, "open_capture", fake_open)
    monkeypatch.setattr(scapy.sendrecv, "sniff", fake_sniff)
    out = tmp_path / "live.trz"
    ns = zelos_sdk.TraceNamespace("test")
    with zelos_sdk.TraceWriter(str(out), namespace=ns):
        source = zelos_sdk.TraceSource("V2G", namespace=ns)
        codecs = {
            b.interface: make_codec("V2G", b, PacketOptions(), source=source) for b in branches
        }
        # A refused interface is skipped; the others keep capturing.
        assert live.sniff_into(codecs) == ["bad0"]
        for t in threading.enumerate():
            if t.name.startswith("v2g-"):
                t.join()
        for codec in codecs.values():
            codec.flush()

    events = _events(out)
    assert {"*/V2G/en0/message", "*/V2G/en0/packets", "*/V2G/eth0_1/slac"} <= events.keys()
    # The SLAC-fail capture never reached V2GTP: nothing of en0's leaks into eth0_1.
    assert "*/V2G/en0/pre_charge_res" in events
    assert "*/V2G/eth0_1/pre_charge_res" not in events


def test_convert_writes_packet_rows_in_capture_span(tmp_path: Path) -> None:
    pa = pytest.importorskip("pyarrow")
    out = tmp_path / "out.trz"
    stats = convert_capture(FIXTURE, out)
    with PcapReader(str(FIXTURE)) as reader:
        times = [int(float(p.time) * 1e9) for p in reader]
    assert stats.packets == len(times) == 589

    field = f"*/V2G/{FIXTURE.stem}/packets.frame_no"
    assert _events(out)[field.rsplit(".", 1)[0]] == "zelos.packet.v1"
    reader = zelos_sdk.TraceReader(str(out))
    reader.open()
    try:
        tr = reader.time_range()
        segs = [s.id for s in reader.list_data_segments()]
        res = reader.query(data_segment_ids=segs, fields=[field], start=tr.start, end=tr.end)
        col = pa.ipc.open_stream(res.to_arrow()).read_all().column(field[2:])
    finally:
        reader.close()
    assert len({v for v in col.to_pylist() if v is not None}) == len(times)
    # No wall-clock stats row stretches the range past the capture.
    assert min(times) <= _ns(tr.start) and _ns(tr.end) <= max(times)


def test_repeated_convert_does_not_leak_schemas(tmp_path: Path) -> None:
    convert_capture(FIXTURE, tmp_path / "a.trz")
    convert_capture(SLAC_FAIL, tmp_path / "b.trz")
    paths = _events(tmp_path / "b.trz")
    assert paths and all(p.startswith(f"*/V2G/{SLAC_FAIL.stem}/") for p in paths)
