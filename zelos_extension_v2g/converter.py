"""pcap -> .trz conversion, shared by the `convert` CLI command and the
`Convert` action so the two surfaces cannot diverge.

Distinct from `capture.replay_pcap`, which decodes into the *live* namespace so
rows stream to a running agent. Conversion produces a file and nothing else: it
builds its own `TraceNamespace` + `TraceWriter`, so `zelos_sdk.init()` never
runs and no agent has to be reachable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .capture import make_decoder
from .constants import DEFAULT_PREFIX
from .decode import V2gConfig, counters, health

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = (".pcap", ".pcapng")
#: Decoded by zelos-packet, which decides by magic bytes, not by name.
COMPRESSED_SUFFIXES = (".gz", ".zst")


def _strip_suffix(name: str, suffixes: tuple[str, ...]) -> str:
    for suffix in suffixes:
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def capture_stem(path: Path) -> str:
    """`run1` for run1.pcap, run1.pcapng.gz and run1.zst alike."""
    return _strip_suffix(_strip_suffix(path.name, COMPRESSED_SUFFIXES), SUPPORTED_FORMATS)


def resolve_output(
    input_file: Path, output: Path | None = None, *, overwrite: bool = False
) -> Path:
    """Where one input's `.trz` goes: the input's capture stem plus `.trz` unless named.

    Raises:
        ValueError: the resolved output is the input file.
        FileExistsError: the output exists and `overwrite` is False.
    """
    out = (
        Path(output).expanduser()
        if output is not None
        else input_file.with_name(f"{capture_stem(input_file)}.trz")
    )
    if out.suffix.lower() != ".trz":
        out = out.with_suffix(".trz")
    if out == input_file:
        raise ValueError(f"Output path is the input file: {out}")
    if out.exists():
        if not overwrite:
            raise FileExistsError(f"Output exists: {out} (use --force / enable Overwrite)")
        out.unlink()
    return out


def convert_pcap(
    input_file: str | Path,
    output_file: str | Path,
    *,
    v2g: V2gConfig = V2gConfig(),
    prefix: str = DEFAULT_PREFIX,
) -> dict[str, Any]:
    """Convert one pcap/pcapng, optionally gzip or zstd compressed, to `output_file`.

    Rows keep the capture's own timestamps. No agent, no `zelos_sdk.init()`. A
    failed decode removes the partial file: a stub .trz would look exactly like
    a successful conversion of an empty capture.

    Raises:
        FileNotFoundError: the input does not exist.
    """
    import zelos_sdk

    source = Path(input_file).expanduser()
    destination = Path(output_file).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Converting %s -> %s", source, destination)
    namespace = zelos_sdk.TraceNamespace("converter")
    try:
        with zelos_sdk.TraceWriter(str(destination), namespace=namespace):
            decoder = make_decoder(
                capture_stem(source), prefix, namespace=namespace, cached=False, v2g=v2g
            )
            packets = decoder.convert_file(str(source))
            decoder.flush()
            decoded = counters(decoder.metrics())
    except KeyboardInterrupt:
        logger.error("Aborted; partial trace kept: %s", destination)
        raise
    except BaseException:
        destination.unlink(missing_ok=True)
        logger.error("Conversion of %s failed; removed partial %s", source.name, destination)
        raise

    logger.info("Converted %s: %d packets -> %s", source.name, packets, destination)
    return {
        **health([{"name": source.name, **decoded}]),
        "input_file": str(source),
        "output_file": str(destination),
        "packets": packets,
        **decoded,
    }
