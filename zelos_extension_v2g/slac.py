"""HomePlug-AV SLAC (ISO 15118-3) body decode + init diagnostics.

SLAC frames are HomePlug-AV management messages (not EXI): a 5-byte header
(MMV + MMTYPE + FMI) then a message body. We decode the fields most useful for
diagnosing SLAC *init* — the attenuation profile and the run/match identifiers —
and summarize the pairing sequence (matched? how long? retries?). Offsets are
validated against captured DIN 70121 sessions.
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass
class SlacSummary:
    matched: bool
    duration_ms: float | None
    mnbc_sounds: int
    start_atten_inds: int
    parm_reqs: int
    set_key: bool
    run_id: str
    nid: str
    atten_min: int | None
    atten_max: int | None
    atten_mean: float | None


def summarize(frames: list) -> SlacSummary | None:
    """Derive SLAC-init health from the frame sequence + timing."""
    if not frames:
        return None
    names = [f.name for f in frames]

    def first_ts(name: str) -> float | None:
        return next((f.ts for f in frames if f.name == name), None)

    matched = "CM_SLAC_MATCH.CNF" in names
    t0, t_match = first_ts("CM_SLAC_PARM.REQ"), first_ts("CM_SLAC_MATCH.CNF")
    duration_ms = (t_match - t0) * 1000 if matched and t0 and t_match else None

    run_id, nid, aag = "", "", None
    for f in frames:
        if f.name == "CM_ATTEN_CHAR.IND" and aag is None:
            a = parse_atten_char_ind(f.payload)
            if a:
                aag, run_id = a["aag"], a["run_id"]
        elif f.name == "CM_SLAC_MATCH.CNF":
            m = parse_slac_match_cnf(f.payload)
            if m:
                nid = m["nid"]
                run_id = run_id or m["run_id"]

    return SlacSummary(
        matched=matched,
        duration_ms=duration_ms,
        mnbc_sounds=names.count("CM_MNBC_SOUND.IND"),
        start_atten_inds=names.count("CM_START_ATTEN_CHAR.IND"),
        parm_reqs=names.count("CM_SLAC_PARM.REQ"),
        set_key="CM_SET_KEY.REQ" in names,
        run_id=run_id,
        nid=nid,
        atten_min=min(aag) if aag else None,
        atten_max=max(aag) if aag else None,
        atten_mean=sum(aag) / len(aag) if aag else None,
    )
