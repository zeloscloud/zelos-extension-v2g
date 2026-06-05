"""ctypes binding to the bundled libcbv2g EXI-decode shim.

The shim (native/v2g_din_shim.c statically linked against EVerest's libcbv2g) is
prebuilt per platform and shipped under ``_lib/``. We load it with stdlib ``ctypes``
— no Python dependency, no compiler on the target. If no artifact exists for the
running platform, decode degrades gracefully to ``None`` (Layer-1 framing still works).
"""

from __future__ import annotations

import ctypes
import json
import logging
import platform
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_LIB_DIR = Path(__file__).parent / "_lib"
# Capacity of the JSON buffer the shim decodes one message into. Decoded telemetry
# objects are small (a handful of numeric/short-string fields, typically <500 B); this
# is generous headroom. If a message's JSON ever exceeds it the shim truncates, which
# we detect (see _decode) rather than emit malformed JSON.
_OUT_CAP = 16384


def _artifact_name() -> str:
    system = platform.system().lower()  # "darwin" | "linux"
    if system not in ("darwin", "linux"):
        system = "linux"
    machine = platform.machine().lower()  # "arm64" | "x86_64" | "aarch64"
    if machine == "aarch64":
        machine = "arm64"
    ext = "dylib" if system == "darwin" else "so"
    return f"libv2gshim-{system}-{machine}.{ext}"


@lru_cache(maxsize=1)
def _load() -> ctypes.CDLL | None:
    path = _LIB_DIR / _artifact_name()
    if not path.exists():
        return None
    lib = ctypes.CDLL(str(path))
    for fn in ("v2g_din_decode_json", "v2g_iso2_decode_json", "v2g_apphand_decode_json"):
        handle = getattr(lib, fn)
        handle.restype = ctypes.c_int
        handle.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    return lib


def available() -> bool:
    """True if a decode library is bundled for the running platform."""
    return _load() is not None


def _decode(fn_name: str, exi: bytes) -> dict | None:
    lib = _load()
    if lib is None:
        return None
    # `exi` is binary (may contain NUL): ctypes passes a pointer to the full bytes
    # buffer, and the C side reads exactly `len(exi)` bytes (not strlen), so NULs
    # are safe here.
    out = ctypes.create_string_buffer(_OUT_CAP)
    # The shim returns bytes written, or the would-be length if it overran `cap`
    # (vsnprintf semantics); n >= cap therefore means the JSON was truncated.
    n = getattr(lib, fn_name)(exi, len(exi), out, _OUT_CAP)
    if n <= 0:
        return None
    if n >= _OUT_CAP:
        logger.warning("%s output truncated at %d bytes; field decode dropped", fn_name, _OUT_CAP)
        return None
    try:
        return json.loads(out.raw[:n])
    except (ValueError, UnicodeDecodeError):
        return None


def decode_din(exi: bytes) -> dict | None:
    """Decode one DIN 70121 V2G application message to a dict of telemetry fields.

    Returns ``None`` if no library is bundled for this platform, or the bytes are
    not a decodable DIN message (e.g. the supportedAppProtocol handshake — use
    :func:`decode_sap` for that).
    """
    return _decode("v2g_din_decode_json", exi)


def decode_iso2(exi: bytes) -> dict | None:
    """Decode one ISO 15118-2 V2G application message to a dict of telemetry fields."""
    return _decode("v2g_iso2_decode_json", exi)


def decode_sap(exi: bytes) -> dict | None:
    """Decode a supportedAppProtocol (SAP) handshake message → negotiated protocol."""
    return _decode("v2g_apphand_decode_json", exi)
