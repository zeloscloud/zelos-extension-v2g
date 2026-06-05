"""Incremental V2G stream decoder — for live capture and pcap replay.

Feeds scapy packets one at a time, maintaining per-stream TCP reassembly, and
invokes callbacks as SLAC frames, SDP frames, and V2G application messages
complete. Shares the per-frame parse helpers and record types with the batch
decoder (:mod:`pcap`); the only difference is incremental, length-prefixed V2GTP
framing instead of a whole-capture scan.
"""

from __future__ import annotations

import struct
from collections.abc import Callable

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from . import protocol as p
from .pcap import SdpFrame, SlacFrame, V2gMessage, _parse_sdp, _parse_slac


class _Framer:
    """Incremental, length-prefixed V2GTP framer for one TCP direction."""

    def __init__(self) -> None:
        self.buf = bytearray()

    def feed(self, data: bytes):
        """Append bytes; yield (payload_type, body) for each complete V2GTP frame."""
        self.buf += data
        while len(self.buf) >= p.V2GTP_HEADER_LEN:
            if self.buf[0] != p.V2GTP_VERSION or self.buf[1] != p.V2GTP_INVERSE_VERSION:
                del self.buf[0]  # resync past a stray byte
                continue
            plen = struct.unpack(">I", self.buf[4:8])[0]
            total = p.V2GTP_HEADER_LEN + plen
            if len(self.buf) < total:
                break  # frame not fully arrived yet
            ptype = struct.unpack(">H", self.buf[2:4])[0]
            body = bytes(self.buf[p.V2GTP_HEADER_LEN : total])
            del self.buf[:total]
            yield ptype, body


class V2gStreamDecoder:
    """Stateful packet -> record decoder. Call :meth:`feed_packet` per scapy packet."""

    def __init__(
        self,
        on_slac: Callable[[SlacFrame], object] | None = None,
        on_sdp: Callable[[SdpFrame], object] | None = None,
        on_message: Callable[[V2gMessage], object] | None = None,
    ) -> None:
        self.on_slac = on_slac
        self.on_sdp = on_sdp
        self.on_message = on_message
        self._framers: dict[tuple, _Framer] = {}
        self._index = 0
        self.secc_ip: str | None = None
        self.secc_port: int | None = None

    @property
    def message_count(self) -> int:
        """Number of V2G application messages decoded so far."""
        return self._index

    def feed_packet(self, pkt) -> None:
        if Ether not in pkt:
            return
        ts = float(pkt.time)
        eth = pkt[Ether]

        if eth.type == p.ETHERTYPE_HOMEPLUG_AV:
            frame = _parse_slac(ts, bytes(eth.payload), eth.src, eth.dst)
            if frame is not None and self.on_slac:
                self.on_slac(frame)
            return
        if IPv6 not in pkt:
            return
        ip = pkt[IPv6]

        if UDP in pkt:
            udp = pkt[UDP]
            if p.SDP_UDP_PORT in (udp.sport, udp.dport):
                for ptype, body in _Framer().feed(bytes(udp.payload)):
                    sdp = _parse_sdp(ts, body, ptype)
                    if sdp.kind == "response":
                        self.secc_ip, self.secc_port = sdp.secc_ip, sdp.secc_port
                    if self.on_sdp:
                        self.on_sdp(sdp)
        elif TCP in pkt:
            data = bytes(pkt[TCP].payload)
            if not data:
                return
            key = (ip.src, pkt[TCP].sport, ip.dst, pkt[TCP].dport)
            framer = self._framers.setdefault(key, _Framer())
            for ptype, body in framer.feed(data):
                msg = V2gMessage(
                    ts=ts,
                    index=self._index,
                    direction=self._direction(key),
                    payload_type=ptype,
                    length=len(body),
                    exi=body,
                )
                self._index += 1
                if self.on_message:
                    self.on_message(msg)

    def _direction(self, key: tuple) -> str:
        src_ip, sport, dst_ip, dport = key
        return p.v2g_direction(src_ip, sport, dst_ip, dport, self.secc_ip, self.secc_port)
