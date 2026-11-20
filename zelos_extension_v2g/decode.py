"""The one seam onto zelos-packet's V2G decoder.

The decoder is switched on by keyword arguments on `PacketCapture` and
`PacketDecoder`. This module builds those keywords, says whether the installed
package has them, and names the counters the decoder reports. Nothing else in
the extension spells a V2G keyword.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from . import pkg

#: First zelos-packet release that decodes ISO 15118-20 and TLS sessions.
MIN_PACKET_VERSION = "0.0.7"

#: `zelos_packet.Metrics` counters reported: rows the trace refused, then the V2G decoder's.
COUNTERS = (
    "emit_errors",
    "flush_errors",
    "v2g_slac_frames",
    "v2g_slac_malformed",
    "v2g_sdp_frames",
    "v2g_messages",
    "v2g_decoded",
    "v2g_undecoded",
    "v2g_grammar_inferred",
    "v2g_framing_errors",
    "v2g_oversize",
    "v2g_tcp_gaps",
    "v2g_tcp_retransmissions",
    "v2g_streams_evicted",
    "v2g_tls_connections",
    "v2g_tls_decrypted",
    "v2g_tls_secrets_seen",
    "v2g_tls_no_secret",
    "v2g_tls_no_handshake",
    "v2g_tls_unsupported",
    "v2g_tls_auth_failures",
    "v2g_tls_buffer_overflow",
)

#: Capture and decoder counters that, non-zero, mean traffic was lost or seen and not decoded.
PROBLEMS = (
    "kernel_drops",
    "packets_dropped_agent",
    "read_errors",
    "emit_errors",
    "flush_errors",
    "v2g_slac_malformed",
    "v2g_undecoded",
    "v2g_framing_errors",
    "v2g_oversize",
    "v2g_tcp_gaps",
    "v2g_streams_evicted",
    "v2g_tls_no_secret",
    "v2g_tls_no_handshake",
    "v2g_tls_unsupported",
    "v2g_tls_auth_failures",
    "v2g_tls_buffer_overflow",
)


class ConfigError(ValueError):
    """The configuration cannot be turned into a capture."""


@dataclass(frozen=True)
class V2gConfig:
    """What the decoder is told. Shared by capture, replay and conversion."""

    tls_keylog: str | None = None

    def kwargs(self) -> dict[str, Any]:
        """The native keyword arguments, `PacketCapture` and `PacketDecoder` alike."""
        return {"v2g": True, "tls_keylog": self.tls_keylog}


def parse_v2g(raw: object, *, must_exist: bool) -> V2gConfig:
    """A `tls_keylog` setting as a :class:`V2gConfig`; empty is no key log.

    A live capture follows the file as it grows, so it may not exist yet. A
    replay or conversion reads it once, up front (`must_exist`).

    Raises:
        ConfigError: `must_exist` and the file does not.
    """
    text = str(raw or "").strip()
    if not text:
        return V2gConfig()
    path = Path(text).expanduser().resolve()
    if must_exist and not path.is_file():
        raise ConfigError(f"TLS key log file not found: {path}")
    return V2gConfig(tls_keylog=str(path))


def installed_version() -> str:
    try:
        return metadata.version("zelos-packet")
    except metadata.PackageNotFoundError:
        return "none"


def supported() -> bool:
    """Whether the installed zelos-packet has the V2G decoder with TLS.

    Probed, not version-compared, so a local build counts.
    """
    return pkg.available() and hasattr(pkg.module().Metrics, "v2g_tls_decrypted")


def require() -> None:
    """Raise unless the installed zelos-packet decodes V2G."""
    if not pkg.available():
        raise RuntimeError(pkg.skip_reason())
    if not supported():
        raise RuntimeError(
            f"V2G decode needs zelos-packet>={MIN_PACKET_VERSION}; installed {installed_version()}"
        )


def health(rows: list[dict[str, Any]]) -> dict[str, str]:
    """`status`, and a `message` unless it is success, for counter rows: error
    when a capture has ended, warning when a `PROBLEMS` counter is non-zero."""
    ended = [str(r["name"]) for r in rows if not r.get("running", True)]
    if ended:
        return {
            "status": "error",
            "message": f"Capture ended on {', '.join(ended)}: see its 'error' and the "
            "extension log. Restart the extension to capture again.",
        }
    bad = [f"{r['name']} {k}={r[k]}" for r in rows for k in PROBLEMS if r.get(k)]
    if bad:
        return {"status": "warning", "message": f"Traffic lost or not decoded: {', '.join(bad)}."}
    return {"status": "success"}


def counters(metrics: Any) -> dict[str, int]:
    """The V2G counters off a `zelos_packet.Metrics`; absent ones read 0."""
    return {name: int(getattr(metrics, name, 0) or 0) for name in COUNTERS}
