"""Convert a capture (.pcap/.pcapng) to a Zelos trace (.trz).

Mirrors the zelos-extension-can converter: decode into records, then emit them
through a codec into an isolated TraceNamespace + TraceWriter so converted data
never mixes with any live session.

Two entry points:

- :func:`convert_v2g_pcap` — the original V2G-only batch path (kept intact; the
  test-suite and the well-verified telemetry path depend on it).
- :func:`convert_capture` — a single-pass, multi-protocol path that dispatches
  each frame by link layer: SocketCAN records → ``zelos-can``'s ``CanDecoder``,
  Ethernet / IPv6 / HomePlug-AV → the V2G decoder. Both write one shared
  namespace, so a capture carrying **both** CAN and V2G (e.g. a bench recording
  of a charging session) becomes one time-aligned ``.trz`` with ``can*/*`` and
  ``v2g/*`` on the same clock. A CAN-only or V2G-only capture falls out of the
  same pass — whichever decoder matches fires.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import zelos_sdk

from .can_ingest import CanIngest
from .codec import ConversionStats, V2gCodec
from .pcap import decode_session, link_frame
from .socketcan import parse_socketcan
from .stream import V2gStreamDecoder

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


def convert_v2g_pcap(input_file: Path, output_file: Path) -> ConversionStats:
    """Convert a V2G ``.pcap`` to ``.trz``. Timestamps are preserved as captured.

    Raises:
        FileNotFoundError: input file missing.
        ValueError: unsupported extension or unparseable capture.
    """
    input_file = Path(input_file)
    output_file = Path(output_file)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    if input_file.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported format '{input_file.suffix}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
        )

    logger.info("Decoding %s", input_file)
    session = decode_session(input_file)

    logger.info("Converting %s -> %s", input_file, output_file)
    converter_namespace = zelos_sdk.TraceNamespace("converter")
    # Exiting the context calls TraceWriter.close(), which force-flushes all buffered
    # events before returning (zelos-sdk >= 0.0.10a5), so no post-write settle is needed.
    with zelos_sdk.TraceWriter(str(output_file), namespace=converter_namespace):
        codec = V2gCodec(namespace=converter_namespace)
        stats = codec.process(session)

    logger.info("Conversion complete: %s", stats.to_dict())
    return stats


@dataclass
class CaptureStats:
    """Combined stats for a multi-protocol convert (``convert_capture``)."""

    v2g: ConversionStats = field(default_factory=ConversionStats)
    can_frames: int = 0
    can_decoded_frames: int = 0
    can_unknown_ids: int = 0
    dbc: str | None = None
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "v2g": self.v2g.to_dict(),
            "can_frames": self.can_frames,
            "can_decoded_frames": self.can_decoded_frames,
            "can_unknown_ids": self.can_unknown_ids,
            "dbc": self.dbc,
            "duration_seconds": round(self.duration_seconds, 3)
            if self.duration_seconds is not None
            else None,
        }


def _dispatch_capture(input_file: Path, v2g_decoder: V2gStreamDecoder, on_can_frame) -> None:
    """Read a capture once and route each frame: SocketCAN records to
    ``on_can_frame``, Ethernet / IPv6 / HomePlug-AV to the V2G stream decoder.

    scapy reads the pcap/pcapng container but has no dissector for
    ``LINKTYPE_CAN_SOCKETCAN`` (227), so it hands those records back as raw
    bytes — anything with no Ethernet/SLL link frame is a SocketCAN candidate.
    """
    from scapy.packet import Raw
    from scapy.utils import PcapReader

    with PcapReader(str(input_file)) as reader:
        for pkt in reader:
            if link_frame(pkt) is None:
                raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else bytes(pkt)
                frame = parse_socketcan(float(pkt.time), raw)
                if frame is not None:
                    on_can_frame(frame)
                continue
            v2g_decoder.feed_packet(pkt)


def convert_capture(
    input_file: Path, output_file: Path, dbc: Path | str | None = None
) -> CaptureStats:
    """Convert any capture to ``.trz``, decoding both CAN and V2G in one pass.

    SocketCAN frames become ``can_raw/*`` rows (plus decoded ``can/<message>``
    rows when ``dbc`` is given); V2G frames become the usual ``v2g/*`` rows. Both
    share one namespace, so a combined CAN+V2G capture yields one time-aligned
    trace. Timestamps are preserved as captured.

    Raises:
        FileNotFoundError: input (or ``dbc``) file missing.
        ValueError: unsupported extension.
    """
    input_file = Path(input_file)
    output_file = Path(output_file)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    if input_file.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported format '{input_file.suffix}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    if dbc is not None:
        dbc = Path(dbc)
        if not dbc.exists():
            raise FileNotFoundError(f"DBC file not found: {dbc}")

    logger.info("Converting %s -> %s", input_file, output_file)
    ns = zelos_sdk.TraceNamespace("converter")
    v2g_stats = ConversionStats()
    span: dict[str, float | None] = {"first": None, "last": None}

    def track(ts: float) -> None:
        if span["first"] is None or ts < span["first"]:
            span["first"] = ts
        if span["last"] is None or ts > span["last"]:
            span["last"] = ts

    # The CAN decoder is created lazily on the first SocketCAN frame, so a
    # pure-V2G capture produces no empty can* tables.
    can: dict[str, CanIngest | None] = {"ingest": None}

    def on_can(f) -> None:
        track(f.ts)
        if can["ingest"] is None:
            can["ingest"] = CanIngest(ns, dbc=str(dbc) if dbc else None)
        can["ingest"].emit(f)

    def on_slac(f) -> None:
        track(f.ts)
        v2g.emit_slac(f)
        v2g_stats.slac_frames += 1

    def on_sdp(f) -> None:
        track(f.ts)
        v2g.emit_sdp(f)
        v2g_stats.sdp_frames += 1

    def on_message(m) -> None:
        track(m.ts)
        v2g_stats.messages += 1
        _decoded, dialect, emitted = v2g.emit_message(m)
        if emitted:
            v2g_stats.decoded_messages += 1
        if dialect and v2g_stats.protocol is None:
            v2g_stats.protocol = dialect

    # Exiting the context force-flushes buffered events (zelos-sdk >= 0.0.10a5).
    with zelos_sdk.TraceWriter(str(output_file), namespace=ns):
        v2g = V2gCodec(namespace=ns)
        v2g_decoder = V2gStreamDecoder(on_slac=on_slac, on_sdp=on_sdp, on_message=on_message)
        _dispatch_capture(input_file, v2g_decoder, on_can)

    if span["first"] is not None and span["last"] is not None:
        duration = span["last"] - span["first"]
        v2g_stats.duration_seconds = duration
    else:
        duration = None

    stats = CaptureStats(v2g=v2g_stats, dbc=str(dbc) if dbc else None, duration_seconds=duration)
    if can["ingest"] is not None:
        m = can["ingest"].metrics()
        stats.can_frames = m.messages_received
        stats.can_decoded_frames = m.messages_decoded
        stats.can_unknown_ids = m.unknown_messages
        stats.dbc = can["ingest"].dbc

    logger.info("Conversion complete: %s", stats.to_dict())
    return stats
