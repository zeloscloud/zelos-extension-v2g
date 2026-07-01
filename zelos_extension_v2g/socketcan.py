"""Parse ``LINKTYPE_CAN_SOCKETCAN`` (227) frames out of a capture.

Wireshark/tcpdump can capture a SocketCAN interface (``can0``) just like an
Ethernet one; the result is a pcap/pcapng whose records are raw SocketCAN
frames. scapy reads the *container* fine but hands these records back as
undissected bytes (it has no dissector for linktype 227), so we parse the fixed
classic-CAN frame ourselves and feed the fields to ``zelos_can.CanDecoder``.
Layout (pcap encapsulation — the 4-byte id/flags word is **network byte order**,
per the linktype spec):

    0..3  CAN ID + flags (big-endian): bit31 EFF, bit30 RTR, bit29 ERR
    4     payload length (0..8 for classic CAN)
    5     FD flags (0 for classic)
    6..7  reserved
    8..15 up to 8 data bytes

CAN FD (72-byte records) is intentionally not handled here — classic frames are
what the V2G/EV benches this extension targets put on the wire.
"""

from __future__ import annotations

from dataclasses import dataclass

# SocketCAN can_id bit flags (linux/can.h).
CAN_EFF_FLAG = 0x80000000  # extended (29-bit) frame format
CAN_RTR_FLAG = 0x40000000  # remote transmission request
CAN_ERR_FLAG = 0x20000000  # error frame
CAN_EFF_MASK = 0x1FFFFFFF
CAN_SFF_MASK = 0x000007FF

# Classic-CAN SocketCAN record: 8-byte header + 8 data bytes, always 16.
SOCKETCAN_FRAME_LEN = 16


@dataclass(slots=True)
class CanFrame:
    """One classic CAN frame, exactly as it appeared on the bus."""

    ts: float
    can_id: int
    extended: bool
    remote: bool
    error: bool
    dlc: int
    data: bytes


def parse_socketcan(ts: float, raw: bytes) -> CanFrame | None:
    """Decode a 16-byte classic SocketCAN record into a :class:`CanFrame`.

    Returns ``None`` for anything that is not a well-formed classic frame (wrong
    length, or a DLC above 8) so the caller can safely try this on every
    undissected record without misreading non-CAN bytes.
    """
    if len(raw) != SOCKETCAN_FRAME_LEN:
        return None
    dlc = raw[4]
    if dlc > 8:
        return None
    id_raw = int.from_bytes(raw[0:4], "big")
    extended = bool(id_raw & CAN_EFF_FLAG)
    can_id = id_raw & (CAN_EFF_MASK if extended else CAN_SFF_MASK)
    return CanFrame(
        ts=ts,
        can_id=can_id,
        extended=extended,
        remote=bool(id_raw & CAN_RTR_FLAG),
        error=bool(id_raw & CAN_ERR_FLAG),
        dlc=dlc,
        data=bytes(raw[8 : 8 + dlc]),
    )
