"""Convert a V2G pcap capture to a Zelos trace (.trz).

Mirrors the zelos-extension-can converter: decode into records, then emit them
through a codec into an isolated TraceNamespace + TraceWriter so converted data
never mixes with any live session.
"""

from __future__ import annotations

import logging
from pathlib import Path

import zelos_sdk

from .codec import ConversionStats, V2gCodec
from .pcap import decode_session

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
