"""Convert a capture (.pcap/.pcapng) to a Zelos trace (.trz).

:func:`convert_capture` reads a capture once and dispatches each frame by link
layer: SocketCAN records → ``zelos-can``'s ``CanDecoder``, everything else → the
V2G codec (plus its raw packet rows). Both write one fresh ``TraceNamespace`` per
conversion, so a combined CAN+V2G capture becomes one time-aligned ``.trz`` and
nothing leaks between conversions in a long-lived process.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import zelos_sdk
from scapy.utils import PcapReader

from .codec import ConversionStats
from .config import (
    DEFAULT_PREFIX,
    Branch,
    PacketOptions,
    branch_name,
    check_prefix,
    database_files,
    make_codec,
)
from .exi import libv2g

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = {".pcap", ".pcapng"}


def resolve_trz_output(input_file: Path, output: Path | None, overwrite: bool) -> Path:
    """Resolve the ``.trz`` output path — shared by the CLI and the action.

    Enforces a ``.trz`` suffix, refuses to overwrite the input, and deletes an
    existing output only when ``overwrite`` is set.

    Raises:
        ValueError: the resolved output would be the input file.
        FileExistsError: the output exists and ``overwrite`` is False.
    """
    out = output if output else input_file.with_suffix(".trz")
    if out.suffix.lower() != ".trz":
        out = out.with_suffix(".trz")
    if out == input_file:
        raise ValueError("output path cannot be the same as the input")
    if out.exists():
        if not overwrite:
            raise FileExistsError(f"output exists: {out} (enable overwrite to replace)")
        out.unlink()
    return out


@dataclass
class CaptureStats:
    """Combined stats for a multi-protocol convert (``convert_capture``)."""

    v2g: ConversionStats = field(default_factory=ConversionStats)
    packets: int = 0
    can_frames: int = 0
    can_decoded_frames: int = 0
    can_unknown_ids: int = 0
    can_error_frames: int = 0  # skipped: zelos.can.frame.v1 cannot mark an error frame
    can_bad_records: int = 0  # skipped: malformed SocketCAN record
    frame_errors: dict[str, int] = field(default_factory=dict)  # exception type -> frames
    database_files: list[str] = field(default_factory=list)
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "v2g": self.v2g.to_dict(),
            "packets": self.packets,
            "can_frames": self.can_frames,
            "can_decoded_frames": self.can_decoded_frames,
            "can_unknown_ids": self.can_unknown_ids,
            "can_error_frames": self.can_error_frames,
            "can_bad_records": self.can_bad_records,
            "frame_errors": self.frame_errors,
            "database_files": self.database_files,
            "duration_seconds": round(self.duration_seconds, 3)
            if self.duration_seconds is not None
            else None,
        }


def convert_capture(
    input_file: Path,
    output_file: Path,
    dbcs: Sequence[Path | str] = (),
    *,
    prefix: str = DEFAULT_PREFIX,
    log_packets: bool = True,
) -> CaptureStats:
    """Convert any capture to ``.trz``, decoding both CAN and V2G in one pass.

    Rows land at ``<prefix>/<file stem>/...``: the V2G events, a ``zelos.packet.v1``
    row per frame at ``<stem>/packets`` (with ``log_packets``), and SocketCAN frames
    at ``<stem>/CAN/Frame`` (plus ``<stem>/CAN/<message>`` with ``dbcs``, in precedence
    order: a later file wins). Timestamps are preserved as captured. A frame that
    fails to decode is skipped and counted in ``frame_errors``.

    Raises:
        FileNotFoundError: input file missing.
        ValueError: unsupported extension, missing database, or invalid prefix.
    """
    input_file = Path(input_file)
    output_file = Path(output_file)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    if input_file.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported format '{input_file.suffix}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    dbcs = database_files(dbcs)
    check_prefix(prefix)
    if not libv2g.available():
        logger.warning("No libcbv2g shim for this platform; emitting Layer-1 framing only")

    logger.info("Converting %s -> %s", input_file, output_file)
    # Fresh per conversion: a reused namespace would carry earlier schemas along.
    ns = zelos_sdk.TraceNamespace("converter")
    span: dict[str, float | None] = {"first": None, "last": None}

    def track(ts: float) -> None:
        if span["first"] is None or ts < span["first"]:
            span["first"] = ts
        if span["last"] is None or ts > span["last"]:
            span["last"] = ts

    # Exiting the context force-flushes buffered events; packet rows are pushed
    # explicitly first (`decode_frame` buffers on its own side).
    with zelos_sdk.TraceWriter(str(output_file), namespace=ns):
        branch = Branch(branch_name(input_file.stem))
        options = PacketOptions(log_packets=log_packets)
        v2g = make_codec(prefix, branch, options, namespace=ns, can=True, dbcs=dbcs)
        # SocketCAN frames nest at <stem>/CAN, created on the first one, so a pure-V2G
        # capture gets no CAN tables.
        with PcapReader(str(input_file)) as reader:
            for pkt in reader:
                track(float(pkt.time))
                v2g.feed(pkt)
        v2g.flush()

    v2g.report_errors()
    duration = None
    if span["first"] is not None and span["last"] is not None:
        duration = span["last"] - span["first"]

    stats = CaptureStats(
        v2g=v2g.stats,
        frame_errors=dict(v2g.frame_errors),
        database_files=dbcs,
        duration_seconds=duration,
    )
    if v2g.packets is not None:
        stats.packets = v2g.packets.metrics().packets_emitted
    if v2g.can is not None:
        m = v2g.can.metrics()
        stats.can_frames = m.messages_received
        stats.can_decoded_frames = m.messages_decoded
        stats.can_unknown_ids = m.unknown_messages
        stats.can_error_frames = v2g.can.error_frames
        stats.can_bad_records = v2g.can.bad_records

    logger.info("Conversion complete: %s", stats.to_dict())
    return stats
