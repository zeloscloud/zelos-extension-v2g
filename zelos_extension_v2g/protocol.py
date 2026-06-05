"""V2G protocol constants and lookup tables (pure data, no SDK imports).

Covers the layers visible on the wire in an ISO 15118 / DIN 70121 charging
session: SLAC (HomePlug Green PHY), SDP (SECC Discovery Protocol), and the
V2GTP transport that carries EXI-encoded application messages.

Kept dependency-free so it can be unit-tested in isolation.
"""

from __future__ import annotations

# ─── Ethernet / link layer ────────────────────────────────────────────────
# (scapy dissects Ethernet/IPv6/TCP/UDP; we only need the HomePlug AV ethertype
# to spot SLAC management frames.)

ETHERTYPE_HOMEPLUG_AV = 0x88E1  # HomePlug AV / Green PHY MME frames (SLAC lives here)

# ─── SDP (SECC Discovery Protocol), UDP/15118 ─────────────────────────────

SDP_UDP_PORT = 15118

# SDP security byte (EV's requested / SECC's offered transport security)
SDP_SECURITY = {
    0x00: "TLS",
    0x10: "none",
}
# SDP transport protocol byte
SDP_TRANSPORT = {
    0x00: "TCP",
    0x10: "UDP",
}

# ─── V2GTP (V2G Transfer Protocol) ────────────────────────────────────────

V2GTP_VERSION = 0x01
V2GTP_INVERSE_VERSION = 0xFE
V2GTP_HEADER_LEN = 8

# ─── SLAC (Signal Level Attenuation Characterization) ─────────────────────
# HomePlug AV management message types used by ISO 15118-3 SLAC. The low bits
# of the MMTYPE encode the variant (REQ / CNF / IND / RSP).

# HomePlug AV MMTYPEs use a base value per message, with the low 2 bits selecting
# the variant: REQ=0, CNF=1, IND=2, RSP=3. Generate all four per base so e.g.
# CM_START_ATTEN_CHAR.IND (0x6068+2=0x606A) and CM_ATTEN_CHAR.IND (0x606C+2=0x606E)
# resolve correctly.
_SLAC_BASES = {
    0x6008: "CM_SET_KEY",
    0x601C: "CM_AMP_MAP",
    0x6038: "CM_NW_INFO",
    0x6064: "CM_SLAC_PARM",
    0x6068: "CM_START_ATTEN_CHAR",
    0x606C: "CM_ATTEN_CHAR",
    0x6070: "CM_PKCS_CERT",
    0x6074: "CM_MNBC_SOUND",
    0x6078: "CM_VALIDATE",
    0x607C: "CM_SLAC_MATCH",
    0x6080: "CM_SLAC_USER_DATA",
    0x6084: "CM_ATTEN_PROFILE",
}
_SLAC_VARIANTS = {0: ".REQ", 1: ".CNF", 2: ".IND", 3: ".RSP"}

SLAC_MMTYPES = {
    base + off: name + suffix
    for base, name in _SLAC_BASES.items()
    for off, suffix in _SLAC_VARIANTS.items()
}


def slac_mmtype_name(mmtype: int) -> str:
    """Human-readable SLAC message name, or a hex fallback."""
    return SLAC_MMTYPES.get(mmtype, f"MMTYPE_{mmtype:#06x}")
