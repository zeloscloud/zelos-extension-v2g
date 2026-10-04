"""Per-frame V2G record types and parse helpers.

scapy dissects Ethernet/IPv6/TCP/UDP; these extract the V2G layers on top:

    Ethernet -> IPv6 -> TCP/UDP -> V2GTP -> {EXI payload, SDP}
    Ethernet -> HomePlug AV (0x88e1) -> SLAC management messages

EXI payloads stay raw bytes; field decode is :mod:`zelos_extension_v2g.exi.libv2g`.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Ether

from . import protocol as p

# ─── Decoded record types ─────────────────────────────────────────────────


@dataclass(slots=True)
class SlacFrame:
    ts_ns: int
    mmtype: int
    name: str
    src_mac: str
    dst_mac: str
    payload: bytes = b""  # full MME (header + body), retained raw on the wire


@dataclass(slots=True)
class SdpFrame:
    ts_ns: int
    kind: str  # "request" | "response"
    secc_ip: str | None
    secc_port: int | None
    security: str
    transport: str


@dataclass(slots=True)
class V2gMessage:
    ts_ns: int
    index: int
    direction: str  # "EVCC->SECC" | "SECC->EVCC" | "?"
    payload_type: int
    length: int
    exi: bytes


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


def _parse_slac(ts_ns: int, payload: bytes, src_mac: str, dst_mac: str) -> SlacFrame | None:
    """HomePlug AV MME header: MMV(1) MMTYPE(2, little-endian) FMI(2) ..."""
    if len(payload) < 3:
        return None
    mmtype = struct.unpack("<H", payload[1:3])[0]
    return SlacFrame(
        ts_ns=ts_ns,
        mmtype=mmtype,
        name=p.slac_mmtype_name(mmtype),
        src_mac=src_mac,
        dst_mac=dst_mac,
        payload=payload,
    )


def _parse_sdp(ts_ns: int, body: bytes, ptype: int) -> SdpFrame:
    """SDP request body = [security, transport]; response = SECC IPv6(16) port(2)
    security(1) transport(1)."""
    if ptype == 0x9001 and len(body) >= 20:
        return SdpFrame(
            ts_ns=ts_ns,
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
        ts_ns=ts_ns,
        kind="request",
        secc_ip=None,
        secc_port=None,
        security=security,
        transport=transport,
    )
