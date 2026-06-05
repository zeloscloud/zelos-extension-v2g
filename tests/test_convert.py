"""Tests for the V2G pcap decoder and converter against a real DIN 70121 capture."""

from pathlib import Path

import pytest

from zelos_extension_v2g import slac
from zelos_extension_v2g.converter import convert_v2g_pcap
from zelos_extension_v2g.exi import libv2g
from zelos_extension_v2g.pcap import decode_session

FIXTURE = Path(__file__).parent / "files" / "v2g_din_session.pcap"


def test_decode_session_structure() -> None:
    s = decode_session(FIXTURE)

    # SDP discovery resolved the SECC endpoint.
    assert s.secc_ip is not None
    assert s.secc_port == 56615
    assert len(s.sdp) == 2

    # SLAC pairing handshake is present.
    assert len(s.slac) >= 10

    # V2GTP application messages, both directions, all EXI (0x8001).
    assert len(s.messages) == 974
    assert all(m.payload_type == 0x8001 for m in s.messages)
    directions = {m.direction for m in s.messages}
    assert "EVCC->SECC" in directions
    assert "SECC->EVCC" in directions

    # Messages are time-ordered and carry their raw EXI payload.
    timestamps = [m.ts for m in s.messages]
    assert timestamps == sorted(timestamps)
    assert all(len(m.exi) == m.length for m in s.messages)


def test_convert_produces_trz(tmp_path: Path) -> None:
    out = tmp_path / "session.trz"
    stats = convert_v2g_pcap(FIXTURE, out)

    assert out.exists()
    assert out.stat().st_size > 0
    assert stats.messages == 974
    assert stats.sdp_frames == 2
    assert stats.slac_frames >= 10
    assert stats.duration_seconds is not None and stats.duration_seconds > 0


def test_convert_rejects_unknown_extension(tmp_path: Path) -> None:
    bogus = tmp_path / "capture.txt"
    bogus.write_text("not a pcap")
    try:
        convert_v2g_pcap(bogus, tmp_path / "out.trz")
    except ValueError as e:
        assert "Unsupported format" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for non-.pcap input")


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_layer2_exi_decode() -> None:
    """libcbv2g shim decodes the DIN application messages into telemetry fields."""
    s = decode_session(FIXTURE)

    # SessionSetupReq carries the EVCCID, which equals the EV's SLAC source MAC.
    setup = next(
        d for m in s.messages if (d := libv2g.decode_din(m.exi)) and d["msg"] == "SessionSetupReq"
    )
    assert setup["evccid"] == "8a9c3e788ed1"

    # The session is a long CableCheck loop; SoC is reported and ramps upward.
    socs = [
        d["soc"]
        for m in s.messages
        if (d := libv2g.decode_din(m.exi)) and d.get("msg") == "CableCheckReq"
    ]
    assert len(socs) > 100
    assert socs[0] < socs[-1]  # monotonic-ish ramp
    assert all(0 <= v <= 100 for v in socs)


def test_slac_init_decode() -> None:
    """SLAC bodies + init summary decode (pure-Python; no platform lib needed)."""
    s = decode_session(FIXTURE)
    summary = slac.summarize(s.slac)
    assert summary is not None
    assert summary.matched is True
    assert summary.mnbc_sounds == 10
    assert summary.duration_ms is not None and summary.duration_ms > 0
    assert summary.set_key is True
    assert summary.atten_mean is not None and 0 < summary.atten_mean < 80

    atten = next(
        slac.parse_atten_char_ind(f.payload) for f in s.slac if f.name == "CM_ATTEN_CHAR.IND"
    )
    assert atten["num_groups"] == 58
    assert len(atten["aag"]) == 58


@pytest.mark.skipif(not libv2g.available(), reason="no libcbv2g shim for this platform")
def test_convert_decodes_telemetry(tmp_path: Path) -> None:
    stats = convert_v2g_pcap(FIXTURE, tmp_path / "out.trz")
    assert stats.protocol == "DIN 70121"  # authoritative, from the SAP handshake
    assert stats.decoded_messages >= 969  # DIN field-bearing msgs + the 2 SAP msgs


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
# large fixture — the DIN fixture above exercises the framing/SLAC/SAP path.
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
    decoded message fields landed in the trace schema (the data is in the app)."""
    import zelos_sdk

    out = tmp_path / "roundtrip.trz"
    convert_v2g_pcap(FIXTURE, out)

    reader = zelos_sdk.TraceReader(str(out))
    reader.open()
    try:
        paths = {f.path for src in reader.list_fields() for ev in src.events for f in ev.fields}
    finally:
        reader.close()

    expected = {
        "*/v2g/slac_summary.matched",
        "*/v2g/slac_attenuation.atten_mean",
        "*/v2g/sdp.secc_ip",
        "*/v2g/supported_app_protocol_req.protocol",
        "*/v2g/session_setup_req.evccid",
        "*/v2g/session_setup_res.evse_id",
        "*/v2g/charge_parameter_discovery_req.ev_max_voltage",
        "*/v2g/charge_parameter_discovery_res.evse_max_voltage",
        "*/v2g/cable_check_req.soc",
    }
    missing = expected - paths
    assert not missing, f"missing decoded fields in trace: {sorted(missing)}"


def test_stream_decoder_matches_batch() -> None:
    """The incremental stream decoder (the live/replay path) yields the same records
    as the batch decoder — validated by replaying the fixture through scapy sniff,
    the same callback live capture uses."""
    from scapy.sendrecv import sniff

    from zelos_extension_v2g.stream import V2gStreamDecoder

    batch = decode_session(FIXTURE)
    slac_recs, sdp_recs, msg_recs = [], [], []
    dec = V2gStreamDecoder(
        on_slac=slac_recs.append, on_sdp=sdp_recs.append, on_message=msg_recs.append
    )
    sniff(offline=str(FIXTURE), prn=dec.feed_packet, store=False)

    assert len(slac_recs) == len(batch.slac)
    assert len(sdp_recs) == len(batch.sdp)
    assert len(msg_recs) == len(batch.messages)
    assert sorted(m.exi for m in msg_recs) == sorted(m.exi for m in batch.messages)
    dirs = {m.direction for m in msg_recs}
    assert "EVCC->SECC" in dirs and "SECC->EVCC" in dirs
