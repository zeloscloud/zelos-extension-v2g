"""Tests for the V2G pcap decoder and converter.

Fixtures are standard off-the-shelf captures from the pyPLC project (see
tests/files/README.md): a Tesla Model Y DC session (primary fixture — full DIN
handshake through PreCharge) and a Porsche Taycan SLAC-failure capture.
"""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from zelos_extension_v2g import slac
from zelos_extension_v2g.codec import _FIELD_META, _MSG_FIELDS, _VALUE_TABLES, DIN, ISO2, _ts_ns
from zelos_extension_v2g.config import Branch, PacketOptions, make_codec
from zelos_extension_v2g.converter import convert_capture, resolve_trz_output
from zelos_extension_v2g.exi import libv2g
from zelos_extension_v2g.stream import V2gStreamDecoder

FILES = Path(__file__).parent / "files"
FIXTURE = FILES / "2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng"
SLAC_FAIL = FILES / "2023-05-03_TaycanLeftside_slacFail.pcapng"


def _codec(name: str = "t"):
    """A V2G-only codec in a throwaway namespace (no writer): counts via ``stats``."""
    import zelos_sdk

    ns = zelos_sdk.TraceNamespace("test")
    codec = make_codec("V2G", Branch(name), PacketOptions(log_packets=False), namespace=ns)
    codec.namespace = ns  # the source does not keep its namespace alive
    return codec


def decode_session(path: Path) -> SimpleNamespace:
    """Every SLAC / SDP / V2G record in a capture, via the production stream decoder."""
    from scapy.utils import PcapReader

    s = SimpleNamespace(slac=[], sdp=[], messages=[])
    dec = V2gStreamDecoder(on_slac=s.slac.append, on_sdp=s.sdp.append, on_message=s.messages.append)
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            dec.feed_packet(pkt, _ts_ns(pkt.time))
    s.secc_ip, s.secc_port = dec.secc_ip, dec.secc_port
    return s


def test_decode_session_structure() -> None:
    s = decode_session(FIXTURE)

    # SDP discovery resolved the SECC endpoint.
    assert s.secc_ip is not None
    assert s.secc_port == 15118
    assert len(s.sdp) == 2

    # SLAC pairing handshake is present.
    assert len(s.slac) == 86

    # V2GTP application messages, both directions, all EXI (0x8001).
    assert len(s.messages) == 274
    assert all(m.payload_type == 0x8001 for m in s.messages)
    directions = {m.direction for m in s.messages}
    assert "EVCC->SECC" in directions
    assert "SECC->EVCC" in directions

    # Messages are time-ordered and carry their raw EXI payload.
    timestamps = [m.ts_ns for m in s.messages]
    assert timestamps == sorted(timestamps)
    assert all(len(m.exi) == m.length for m in s.messages)
    assert [m.index for m in s.messages] == list(range(274))


def test_convert_produces_trz(tmp_path: Path) -> None:
    out = tmp_path / "session.trz"
    capture = convert_capture(FIXTURE, out)
    stats = capture.v2g

    assert out.exists()
    assert out.stat().st_size > 0
    assert stats.messages == 274
    assert stats.sdp_frames == 2
    assert stats.slac_frames == 86
    assert capture.duration_seconds is not None and capture.duration_seconds > 0
    assert capture.frame_errors == {}


def test_convert_rejects_unknown_extension(tmp_path: Path) -> None:
    bogus = tmp_path / "capture.txt"
    bogus.write_text("not a pcap")
    try:
        convert_capture(bogus, tmp_path / "out.trz")
    except ValueError as e:
        assert "Unsupported format" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for non-.pcap input")


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_layer2_exi_decode() -> None:
    """libcbv2g shim decodes the DIN application messages into telemetry fields."""
    s = decode_session(FIXTURE)

    # SessionSetupReq carries the EVCCID (the EV's identifier).
    setup = next(
        d for m in s.messages if (d := libv2g.decode_din(m.exi)) and d["msg"] == "SessionSetupReq"
    )
    assert setup["evccid"] == "98ed5cdad998"

    # CableCheck reports SoC (this session holds steady at 55%).
    socs = [
        d["soc"]
        for m in s.messages
        if (d := libv2g.decode_din(m.exi)) and d.get("msg") == "CableCheckReq"
    ]
    assert socs and all(v == 55 for v in socs)

    # PreCharge ramps the DC link voltage up before contactors close.
    volts = [
        d["evse_present_voltage"]
        for m in s.messages
        if (d := libv2g.decode_din(m.exi)) and d.get("msg") == "PreChargeRes"
    ]
    assert len(volts) > 50
    assert min(volts) < max(volts)  # voltage ramps
    assert max(volts) == pytest.approx(347, abs=5)


def test_slac_frames_present_with_raw_bytes() -> None:
    """SLAC frames are recorded as-is: typed by MMTYPE name, with their raw MME bytes
    retained — the pairing sequence is the bus, verbatim."""
    s = decode_session(FIXTURE)
    names = [f.name for f in s.slac]
    assert "CM_SLAC_PARM.REQ" in names
    assert "CM_SLAC_MATCH.CNF" in names
    assert names.index("CM_SLAC_PARM.REQ") < names.index("CM_SLAC_MATCH.CNF")
    # Every frame keeps its raw bytes for downstream/expert decode.
    assert all(f.payload for f in s.slac)


def test_slac_per_frame_field_decode() -> None:
    """Individual SLAC frames decode into human-readable fields (per-frame, not a
    cross-frame summary): the attenuation profile and the matched NID/NMK."""
    s = decode_session(FIXTURE)

    atten = next(
        slac.parse_atten_char_ind(f.payload) for f in s.slac if f.name == "CM_ATTEN_CHAR.IND"
    )
    assert atten["num_groups"] == 58
    assert len(atten["aag"]) == 58
    assert all(0 <= db <= 80 for db in atten["aag"])  # per-group attenuation in dB

    match = next(
        slac.parse_slac_match_cnf(f.payload) for f in s.slac if f.name == "CM_SLAC_MATCH.CNF"
    )
    assert len(match["nid"]) == 14  # 7-byte network id, hex
    assert len(match["nmk"]) == 32  # 16-byte network membership key, hex
    assert match["run_id"] == atten["run_id"]  # same pairing run


def test_slac_failure_capture() -> None:
    """A real SLAC-init failure (Taycan): repeated PARM.REQ with no MATCH.CNF, and the
    session never reaches SDP or any V2G message. We record exactly that — no inference."""
    s = decode_session(SLAC_FAIL)
    names = [f.name for f in s.slac]
    assert names.count("CM_SLAC_PARM.REQ") >= 2  # the EV retried
    assert "CM_SLAC_MATCH.CNF" not in names  # never matched
    assert s.sdp == []
    assert s.messages == []


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_convert_decodes_telemetry(tmp_path: Path) -> None:
    stats = convert_capture(FIXTURE, tmp_path / "out.trz").v2g
    assert stats.protocol == "DIN 70121"  # factual — the grammar that decoded
    assert stats.decoded_messages >= 260  # nearly every message field-decodes


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_sap_handshake_decode() -> None:
    s = decode_session(FIXTURE)
    req = libv2g.decode_sap(s.messages[0].exi)
    assert req is not None and req["msg"] == "SupportedAppProtocolReq"
    assert req["protocol"] == "urn:din:70121:2012:MsgDef"
    res = libv2g.decode_sap(s.messages[1].exi)
    assert res is not None and res["msg"] == "SupportedAppProtocolRes"


# Real ISO 15118-2 EXI messages lifted from a DC charging capture (dsV2Gshark
# example set). Embedded so the ISO-2 decode path is covered without a second
# large fixture — the DIN fixtures above exercise the framing/SLAC/SAP path.
_ISO2_SESSION_SETUP_RES = bytes.fromhex("809802275de64d834b5d1f11e020256968c0c0c0c0c080")
_ISO2_CURRENT_DEMAND_RES = bytes.fromhex(
    "809802275de64d834b5d1f10e00000002040840861d000c000000021024138041844138105098750095a5a30303030300008"
)


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_iso2_exi_decode() -> None:
    """libcbv2g shim decodes ISO 15118-2 messages (the iso2 grammar, distinct from DIN).

    These same bytes do NOT decode as DIN, confirming the per-dialect dispatch."""
    setup = libv2g.decode_iso2(_ISO2_SESSION_SETUP_RES)
    assert setup is not None
    assert setup["msg"] == "SessionSetupRes"
    assert setup["evse_id"] == "ZZ00000"  # ISO-2 EVSEID is a string (DIN is hexBinary)

    demand = libv2g.decode_iso2(_ISO2_CURRENT_DEMAND_RES)
    assert demand is not None
    assert demand["msg"] == "CurrentDemandRes"
    assert demand["evse_present_voltage"] == pytest.approx(371.8, abs=0.1)
    assert demand["evse_status_code"] == 1  # EVSE_Ready

    # The ISO-2 bytes are not valid DIN — codec dispatch relies on this falling through.
    assert libv2g.decode_din(_ISO2_CURRENT_DEMAND_RES) is None


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_trace_fields_present_via_reader(tmp_path: Path) -> None:
    """Convert, then read the .trz back through zelos_sdk.TraceReader and assert the
    decoded fields landed in the trace schema (the data is in the app)."""
    import zelos_sdk

    out = tmp_path / "roundtrip.trz"
    convert_capture(FIXTURE, out)

    reader = zelos_sdk.TraceReader(str(out))
    reader.open()
    try:
        paths = {f.path for src in reader.list_fields() for ev in src.events for f in ev.fields}
    finally:
        reader.close()

    expected = {
        f"*/V2G/{FIXTURE.stem}/{f}"
        for f in (
            "slac.data",  # raw SLAC frame bytes, as-is
            "slac_attenuation.atten_mean",  # per-frame attenuation decode
            "slac_match.nid",  # per-frame matched network id
            "sdp.secc_ip",
            "supported_app_protocol_req.protocol",
            "session_setup_req.evccid",
            "session_setup_res.evse_id",
            "session_setup_res.protocol",
            "session_setup_res.response_code_iso2",
            "charge_parameter_discovery_req.ev_max_voltage",
            "charge_parameter_discovery_res.evse_max_voltage",
            "cable_check_req.soc",
            "pre_charge_res.evse_present_voltage",
        )
    }
    missing = expected - paths
    assert not missing, f"missing decoded fields in trace: {sorted(missing)}"


def test_layer1_without_libv2g(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no shim bundled, Layer-2 field decode is skipped but Layer-1 framing
    (SLAC / SDP / V2GTP message timeline) still converts — graceful degradation."""
    monkeypatch.setattr(libv2g, "available", lambda: False)

    stats = convert_capture(FIXTURE, tmp_path / "layer1.trz").v2g

    assert stats.messages == 274  # framing still works
    assert stats.sdp_frames == 2
    assert stats.slac_frames >= 10
    assert stats.decoded_messages == 0  # no shim -> no field decode
    assert stats.protocol is None  # protocol is only set from a decoded message


def test_resolve_trz_output_rejects_input_path(tmp_path: Path) -> None:
    src = tmp_path / "capture.trz"
    with pytest.raises(ValueError, match="same as the input"):
        resolve_trz_output(src, None, overwrite=False)


def test_resolve_trz_output_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "out.trz"
    out.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        resolve_trz_output(tmp_path / "in.pcap", out, overwrite=False)
    # overwrite=True replaces it and returns the path
    assert resolve_trz_output(tmp_path / "in.pcap", out, overwrite=True) == out
    assert not out.exists()  # the stale output was unlinked


def test_resolve_trz_output_forces_trz_suffix(tmp_path: Path) -> None:
    resolved = resolve_trz_output(tmp_path / "in.pcap", tmp_path / "out.txt", overwrite=False)
    assert resolved.suffix == ".trz"
    assert resolved.name == "out.trz"


def test_live_emits_same_records_as_convert() -> None:
    """Replaying the fixture through the live path emits exactly the records convert
    does — every frame, no synthesized summary, no extra rows."""
    from zelos_extension_v2g.live import replay_into

    codec = _codec()
    replay_into(codec, FIXTURE, realtime=False)
    assert (codec.stats.slac_frames, codec.stats.sdp_frames, codec.stats.messages) == (86, 2, 274)


def test_replay_paces_by_capture_deltas() -> None:
    """Real-time replay releases frames spaced by the capture's actual inter-frame
    deltas (not a fast burst). The scheduled waits are captured without real waiting."""
    import time as _time

    from scapy.utils import PcapReader

    from zelos_extension_v2g.live import replay_into

    with PcapReader(str(SLAC_FAIL)) as reader:
        src = [float(p.time) for p in reader]
    span = src[-1] - src[0]
    assert span > 1.0  # the SLAC retries play out over seconds — a real schedule, not 0

    class _Stop:
        delays: list[float] = []

        def wait(self, d: float) -> bool:
            self.delays.append(d)
            return False

    class _Stamps:
        stamps: list[float] = []

        def feed(self, pkt) -> None:
            self.stamps.append(float(pkt.time))

        def flush(self) -> None: ...

        class stats:
            messages = 0

    stop, codec = _Stop(), _Stamps()
    replay_into(codec, SLAC_FAIL, realtime=True, stop=stop)

    # Frames were paced out to ~the capture span (a fast burst would schedule ~nothing).
    assert stop.delays, "expected real-time pacing to schedule waits"
    assert max(stop.delays) == pytest.approx(span, abs=2.0)
    # One constant shift: stamps land near now with the capture's exact spacing.
    assert codec.stamps[0] == pytest.approx(_time.time(), abs=5.0)
    assert [s - codec.stamps[0] for s in codec.stamps] == pytest.approx(
        [t - src[0] for t in src], abs=1e-6
    )


def test_decode_stream_matches_convert() -> None:
    """Decoding a pcap byte stream (as from `tcpdump -w -` piped to stdin) yields the
    same records as convert — the `decode` subcommand's core path."""
    import io

    from zelos_extension_v2g.live import decode_stream_into

    codec = _codec()
    decode_stream_into(codec, source=io.BytesIO(FIXTURE.read_bytes()))
    assert (codec.stats.slac_frames, codec.stats.sdp_frames, codec.stats.messages) == (86, 2, 274)


def test_cooked_sll_link_layer_decodes_slac() -> None:
    """`tcpdump -i any` yields Linux cooked (SLL) frames, not Ethernet. A SLAC frame in
    that encapsulation must still decode — the link-layer-agnostic seam."""
    from scapy.layers.l2 import CookedLinux
    from scapy.packet import Raw

    from zelos_extension_v2g.pcap import link_frame

    batch = decode_session(FIXTURE)
    parm = next(f for f in batch.slac if f.name == "CM_SLAC_PARM.REQ")
    sll = CookedLinux(proto=0x88E1) / Raw(parm.payload)  # same MME, cooked encapsulation

    ethertype, payload, _src, _dst = link_frame(sll)
    assert ethertype == 0x88E1
    assert payload == parm.payload

    got: list = []
    V2gStreamDecoder(on_slac=got.append).feed_packet(sll, 1)
    assert len(got) == 1
    assert got[0].name == "CM_SLAC_PARM.REQ"  # decoded the same as over Ethernet


def test_msg_fields_cover_shim() -> None:
    """Each decoded event's schema is the message's full field set from the shim, so a
    later instance carrying an optional field the first lacked still logs."""
    shim = (Path(__file__).parents[1] / "native" / "v2g_din_shim.c").read_text()
    emitted: dict[str, set[str]] = {}
    msg = None
    # Message names (`M("X")` or a literal `\"msg\":\"X\"`), then the fields emitted after.
    pattern = r'M\("(\w+)"\)|\\"msg\\":\\"(\w+)\\"|\\"(?!msg\\")(\w+)\\":'
    for m in re.finditer(pattern, shim):
        if m[1] or m[2]:
            msg = m[1] or m[2]
            emitted.setdefault(msg, set())
        else:
            emitted[msg].add(m[3])
    assert {k: set(v) for k, v in _MSG_FIELDS.items()} == {k: v for k, v in emitted.items() if v}
    assert {f for v in _MSG_FIELDS.values() for f in v} <= _FIELD_META.keys()

    codec = _codec()
    base = {"msg": "ChargeParameterDiscoveryReq", "ev_max_voltage": 500.0, "ev_max_current": 1.0}
    assert codec._emit_decoded(base, 1, DIN)
    assert codec._emit_decoded({**base, "bulk_soc": 80, "full_soc": 100}, 2, DIN)

    # Response codes diverge from 20: each grammar writes its own column.
    codec._decoded_event("CableCheckRes")  # registers the schema + value tables
    logged = []
    codec._decoded_events["CableCheckRes"] = SimpleNamespace(
        log_at=lambda _, **kw: logged.append(kw)
    )
    codec._emit_decoded({"msg": "CableCheckRes", "response_code": 23}, 3, ISO2)
    codec._emit_decoded({"msg": "CableCheckRes", "response_code": 20}, 4, DIN)
    assert logged == [
        {"protocol": ISO2, "response_code_iso2": 23},
        {"protocol": DIN, "response_code": 20},
    ]
    assert _VALUE_TABLES["response_code_iso2"][23] == "FAILED_ContactorError"
    assert _VALUE_TABLES["response_code"][20] == "FAILED_EVSEPresentVoltageToLow"
