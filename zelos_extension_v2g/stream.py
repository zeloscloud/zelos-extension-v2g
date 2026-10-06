"""Incremental V2G decoder: the one decode path for convert, live, replay and stdin.

Feeds scapy packets one at a time, maintaining per-stream TCP reassembly, and
invokes callbacks as SLAC frames, SDP frames, and V2G application messages
complete. Reassembly is capture-order concatenation per 4-tuple, minus bytes already
delivered: each direction tracks its next expected sequence number, so a retransmitted
segment is dropped (counted in ``retransmissions``) and a partial overlap is trimmed.
It does not reorder: a segment past a gap is appended as it arrives.
"""

from __future__ import annotations

import struct
from collections.abc import Callable

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6

from . import protocol as p
from .pcap import SdpFrame, SlacFrame, V2gMessage, _parse_sdp, _parse_slac, link_frame


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
        self._next_seq: dict[tuple, int] = {}  # per direction: next undelivered byte
        self.retransmissions = 0  # TCP segments dropped as already delivered
        self._index = 0
        self.secc_ip: str | None = None
        self.secc_port: int | None = None

    def feed_packet(self, pkt, ts_ns: int) -> None:
        ll = link_frame(pkt)

        if ll is not None and ll[0] == p.ETHERTYPE_HOMEPLUG_AV:
            _, payload, src, dst = ll
            frame = _parse_slac(ts_ns, payload, src, dst)
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
                    sdp = _parse_sdp(ts_ns, body, ptype)
                    if sdp.kind == "response":
                        self.secc_ip, self.secc_port = sdp.secc_ip, sdp.secc_port
                    if self.on_sdp:
                        self.on_sdp(sdp)
        elif TCP in pkt:
            tcp = pkt[TCP]
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            if tcp.flags.S:
                self._next_seq.pop(key, None)  # a new connection on this 4-tuple
            data = bytes(tcp.payload)
            if not data:
                return
            nxt = self._next_seq.get(key)
            end = (tcp.seq + len(data)) % 2**32
            if nxt is not None:
                behind = (nxt - tcp.seq) % 2**32  # bytes of this segment already delivered
                if behind < 2**31:  # starts at or before nxt (wraparound-safe)
                    if behind >= len(data):
                        self.retransmissions += 1
                        return
                    data = data[behind:]
            self._next_seq[key] = end
            framer = self._framers.setdefault(key, _Framer())
            for ptype, body in framer.feed(data):
                msg = V2gMessage(
                    ts_ns=ts_ns,
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
