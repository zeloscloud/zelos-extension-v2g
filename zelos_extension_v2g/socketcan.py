"""Parse ``LINKTYPE_CAN_SOCKETCAN`` (227) records out of a capture.

Wireshark/tcpdump can capture a SocketCAN interface (``can0``) just like an
Ethernet one; each record is a raw SocketCAN frame. Layout (pcap encapsulation:
the 4-byte id/flags word is **network byte order**, per the linktype spec):

    0..3  CAN ID + flags (big-endian): bit31 EFF, bit30 RTR, bit29 ERR
    4     payload length (classic 0..8, FD 0..64)
    5     FD flags
    6..7  reserved
    8..   data: 8 bytes (classic, 16-byte record) or 64 (CAN FD, 72-byte record)
"""

from __future__ import annotations

from dataclasses import dataclass

# SocketCAN can_id bit flags (linux/can.h).
CAN_EFF_FLAG = 0x80000000  # extended (29-bit) frame format
CAN_RTR_FLAG = 0x40000000  # remote transmission request
CAN_ERR_FLAG = 0x20000000  # error frame
CAN_EFF_MASK = 0x1FFFFFFF
CAN_SFF_MASK = 0x000007FF

# Record length -> (max payload length, is FD).
_RECORDS = {16: (8, False), 72: (64, True)}


@dataclass(slots=True)
class CanFrame:
    """One CAN frame, exactly as it appeared on the bus."""

    can_id: int
    extended: bool
    remote: bool
    error: bool
    fd: bool
    data: bytes


def parse_socketcan(raw: bytes) -> CanFrame | None:
    """A classic (16-byte) or FD (72-byte) SocketCAN record, or ``None`` if malformed."""
    shape = _RECORDS.get(len(raw))
    if shape is None or raw[4] > shape[0]:
        return None
    id_raw = int.from_bytes(raw[0:4], "big")
    extended = bool(id_raw & CAN_EFF_FLAG)
    return CanFrame(
        can_id=id_raw & (CAN_EFF_MASK if extended else CAN_SFF_MASK),
        extended=extended,
        remote=bool(id_raw & CAN_RTR_FLAG),
        error=bool(id_raw & CAN_ERR_FLAG),
        fd=shape[1],
        data=bytes(raw[8 : 8 + raw[4]]),
    )
