"""Capture decoder for ISO 15118 / DIN 70121 V2G sessions.

scapy reads the container (pcap *or* pcapng) and dissects Ethernet/IPv6/TCP/UDP;
we extract the V2G-specific layers on top:

    Ethernet -> IPv6 -> TCP/UDP -> V2GTP -> {EXI payload, SDP}
    Ethernet -> HomePlug AV (0x88e1) -> SLAC management messages

The output is a :class:`DecodedSession` of timestamped, direction-tagged records.
EXI application payloads are kept as raw bytes; field-level decode is delegated to
libcbv2g (see :mod:`zelos_extension_v2g.exi.libv2g`). Using scapy here also makes a
future live path straightforward (``scapy.sendrecv.sniff``).
"""

from __future__ import annotations

import bisect
import ipaddress
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Ether
from scapy.utils import PcapReader

from . import protocol as p

# ─── Decoded record types ─────────────────────────────────────────────────


@dataclass(slots=True)
class SlacFrame:
    ts: float
    mmtype: int
    name: str
    src_mac: str
    dst_mac: str
    payload: bytes = b""  # full MME (header + body), retained raw on the wire


@dataclass(slots=True)
class SdpFrame:
    ts: float
    kind: str  # "request" | "response"
    secc_ip: str | None
    secc_port: int | None
    security: str
    transport: str


@dataclass(slots=True)
class V2gMessage:
    ts: float
    index: int
    direction: str  # "EVCC->SECC" | "SECC->EVCC" | "?"
    payload_type: int
    length: int
    exi: bytes


@dataclass(slots=True)
class DecodedSession:
    slac: list[SlacFrame] = field(default_factory=list)
    sdp: list[SdpFrame] = field(default_factory=list)
    messages: list[V2gMessage] = field(default_factory=list)
    secc_ip: str | None = None
    secc_port: int | None = None
    start_ts: float | None = None
    end_ts: float | None = None


# ─── per-layer helpers ─────────────────────────────────────────────────────


def link_frame(pkt) -> tuple[int, bytes, str, str] | None:
    """Return ``(ethertype, l2_payload, src_mac, dst_mac)`` for an Ethernet or Linux
    "cooked" (SLL / SLL2) frame, so captures from ``tcpdump -i <eth>`` (Ethernet) and
    ``tcpdump -i any`` (cooked) both decode. Returns ``None`` for any other link layer
    — the IPv6 path still works regardless via ``pkt[IPv6]``. Cooked frames carry no
    destination MAC, so ``dst_mac`` is empty there.
    """
    if Ether in pkt:
        e = pkt[Ether]
        return e.type, bytes(e.payload), e.src, e.dst
    cooked = pkt.getlayer(CookedLinux) or pkt.getlayer(CookedLinuxV2)
    if cooked is not None:
        src = cooked.src
        src_mac = src.hex(":") if isinstance(src, (bytes, bytearray)) else str(src)
        return cooked.proto, bytes(cooked.payload), src_mac, ""
    return None


def _parse_slac(ts: float, payload: bytes, src_mac: str, dst_mac: str) -> SlacFrame | None:
    """HomePlug AV MME header: MMV(1) MMTYPE(2, little-endian) FMI(2) ..."""
    if len(payload) < 3:
        return None
    mmtype = struct.unpack("<H", payload[1:3])[0]
    return SlacFrame(
        ts=ts,
        mmtype=mmtype,
        name=p.slac_mmtype_name(mmtype),
        src_mac=src_mac,
        dst_mac=dst_mac,
        payload=payload,
    )


def _iter_v2gtp(segments: list[tuple[float, bytes]]):
    """Yield (timestamp, payload_type, body) for each V2GTP frame in a stream.

    ``segments`` are this direction's TCP payloads in capture order. They are
    concatenated and scanned for the V2GTP magic; each frame is stamped with the
    capture time of the segment its header starts in.
    """
    if not segments:
        return
    buf = bytearray()
    starts: list[int] = []
    times: list[float] = []
    for ts, data in segments:
        starts.append(len(buf))
        times.append(ts)
        buf += data

    def ts_at(offset: int) -> float:
        i = bisect.bisect_right(starts, offset) - 1
        return times[max(i, 0)]

    i, n = 0, len(buf)
    while i + p.V2GTP_HEADER_LEN <= n:
        if buf[i] == p.V2GTP_VERSION and buf[i + 1] == p.V2GTP_INVERSE_VERSION:
            ptype = struct.unpack(">H", buf[i + 2 : i + 4])[0]
            plen = struct.unpack(">I", buf[i + 4 : i + 8])[0]
            body = bytes(buf[i + p.V2GTP_HEADER_LEN : i + p.V2GTP_HEADER_LEN + plen])
            yield ts_at(i), ptype, body
            i += p.V2GTP_HEADER_LEN + (plen if plen > 0 else 0)
        else:
            i += 1  # resync past stray bytes


def _parse_sdp(ts: float, body: bytes, ptype: int) -> SdpFrame:
    """SDP request body = [security, transport]; response = SECC IPv6(16) port(2)
    security(1) transport(1)."""
    if ptype == 0x9001 and len(body) >= 20:
        return SdpFrame(
            ts=ts,
            kind="response",
            secc_ip=str(ipaddress.IPv6Address(body[0:16])),
            secc_port=struct.unpack(">H", body[16:18])[0],
            security=p.SDP_SECURITY.get(body[18], f"{body[18]:#04x}"),
            transport=p.SDP_TRANSPORT.get(body[19], f"{body[19]:#04x}"),
        )
    # Report exactly what the request carried; mark "unknown" if a byte is absent
    # (truncated frame) rather than inventing a default that wasn't on the wire.
    security = p.SDP_SECURITY.get(body[0], f"{body[0]:#04x}") if len(body) >= 1 else "unknown"
    transport = p.SDP_TRANSPORT.get(body[1], f"{body[1]:#04x}") if len(body) >= 2 else "unknown"
    return SdpFrame(
        ts=ts,
        kind="request",
        secc_ip=None,
        secc_port=None,
        security=security,
        transport=transport,
    )


# ─── top-level entry point ────────────────────────────────────────────────


def decode_session(path: str | Path) -> DecodedSession:
    """Parse a V2G pcap/pcapng into timestamped, direction-tagged records."""
    path = Path(path)
    session = DecodedSession()
    # (src_ip, sport, dst_ip, dport) -> [(ts, payload), ...]
    tcp_streams: dict[tuple, list[tuple[float, bytes]]] = defaultdict(list)

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            ll = link_frame(pkt)
            if ll is not None and ll[0] == p.ETHERTYPE_HOMEPLUG_AV:
                _, payload, src, dst = ll
                slac = _parse_slac(ts, payload, src, dst)
                if slac is not None:
                    session.slac.append(slac)
                continue
            if IPv6 not in pkt:
                continue
            ip = pkt[IPv6]

            if UDP in pkt:
                udp = pkt[UDP]
                if p.SDP_UDP_PORT in (udp.sport, udp.dport):
                    for fts, ptype, body in _iter_v2gtp([(ts, bytes(udp.payload))]):
                        sdp = _parse_sdp(fts, body, ptype)
                        session.sdp.append(sdp)
                        if sdp.kind == "response":
                            session.secc_ip, session.secc_port = sdp.secc_ip, sdp.secc_port
            elif TCP in pkt:
                data = bytes(pkt[TCP].payload)
                if data:
                    tcp_streams[(ip.src, pkt[TCP].sport, ip.dst, pkt[TCP].dport)].append((ts, data))

    # TCP reassembly is capture-order concatenation per 4-tuple: it assumes an
    # in-order, loss-free capture (true for a bridged V2G session) and does not
    # reorder by sequence number or drop retransmits.
    raw: list[V2gMessage] = []
    for (src_ip, sport, dst_ip, dport), segs in tcp_streams.items():
        for fts, ptype, body in _iter_v2gtp(segs):
            raw.append(
                V2gMessage(
                    ts=fts,
                    index=0,
                    direction=p.v2g_direction(
                        src_ip, sport, dst_ip, dport, session.secc_ip, session.secc_port
                    ),
                    payload_type=ptype,
                    length=len(body),
                    exi=body,
                )
            )

    raw.sort(key=lambda m: m.ts)
    for i, msg in enumerate(raw):
        msg.index = i
    session.messages = raw

    all_ts = [r.ts for r in raw] + [s.ts for s in session.slac] + [s.ts for s in session.sdp]
    if all_ts:
        session.start_ts, session.end_ts = min(all_ts), max(all_ts)
    return session
