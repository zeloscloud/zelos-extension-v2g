"""Per-frame SLAC (ISO 15118-3) body decode.

SLAC frames are HomePlug-AV management messages (not EXI): a 5-byte header
(MMV + MMTYPE + FMI) then a message body. These helpers decode the fields carried
by individual frames into human-readable values — the link-attenuation profile and
the run/network identifiers. They are strictly per-frame (each reflects one MME on
the wire); nothing is aggregated across frames. Offsets are validated against
captured DIN 70121 sessions.
"""

from __future__ import annotations

HEADER_LEN = 5  # MMV(1) + MMTYPE(2, little-endian) + FMI(2) — HomePlug AV 1.1


def _body(payload: bytes) -> bytes:
    return payload[HEADER_LEN:]


def parse_atten_char_ind(payload: bytes) -> dict | None:
    """CM_ATTEN_CHAR.IND body: APP, SEC, SRC(6), RunID(8), SourceID(17),
    RespID(17), NumSounds(1), NumGroups(1), AAG[NumGroups] (per-group dB)."""
    b = _body(payload)
    if len(b) < 52:
        return None
    num_sounds, num_groups = b[50], b[51]
    aag = b[52 : 52 + num_groups]
    if num_groups == 0 or len(aag) != num_groups:
        return None
    return {
        "run_id": b[8:16].hex(),
        "num_sounds": num_sounds,
        "num_groups": num_groups,
        "aag": list(aag),
    }


def parse_slac_match_cnf(payload: bytes) -> dict | None:
    """CM_SLAC_MATCH.CNF tail: …RunID(8), RSVD(8), NID(7), RSVD(1), NMK(16)."""
    b = _body(payload)
    if len(b) < 40:
        return None
    return {"run_id": b[-40:-32].hex(), "nid": b[-24:-17].hex(), "nmk": b[-16:].hex()}
