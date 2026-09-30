"""Live V2G capture, pcap replay, and stdin decode -> live Zelos trace.

Every path hands scapy packets to a :class:`V2gCodec` (``codec.feed``), the same
per-frame path the offline converter uses, so live and trace modes produce
identical rows. Replay and stdin re-stamp ``pkt.time`` before the feed, so V2G
events and packet rows share one timestamp.

These assume the SDK is already initialized; ``run_live`` / ``run_decode`` are
the standalone CLI entries.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import zelos_sdk
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .codec import V2gCodec
from .config import (
    DEFAULT_PREFIX,
    LOG_SOURCE_NAME,
    Branch,
    PacketOptions,
    branch_name,
    check_prefix,
    make_codec,
)

logger = logging.getLogger(__name__)

# Capture filter: IPv6 (SDP/V2GTP) + HomePlug AV (SLAC).
_BPF = "ip6 or ether proto 0x88e1"

#: How often live paths push buffered packet rows (`decode_frame` has no timer).
FLUSH_INTERVAL_S = 0.5


def replay_into(codec: V2gCodec, path: str | Path, realtime: bool = True, stop=None) -> None:
    """Replay a capture into ``codec``.

    ``realtime``: shift every timestamp by one constant offset so the first frame
    lands at now, and release each frame when its shifted time comes (like
    ``tcpreplay``). Otherwise feed as fast as possible with the capture's own
    timestamps. ``stop`` (a ``threading.Event``) ends the replay early.
    """
    from scapy.utils import PcapReader

    stop = stop or threading.Event()
    offset: float | None = None
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if realtime:
                ts = float(pkt.time)
                if offset is None:
                    offset = time.time() - ts
                delay = ts + offset - time.time()
                if delay > 0 and stop.wait(delay):
                    break
                pkt.time = ts + offset
            elif stop.is_set():
                break
            codec.feed(pkt)
    codec.flush()
    logger.info("Replay complete: %d V2G messages streamed", codec.stats.messages)


def sniff_into(codecs: dict[str, V2gCodec]) -> None:
    """Sniff every interface in ``codecs`` (keyed by interface) and route each frame
    to its interface's codec by ``pkt.sniffed_on``. Blocks; run it on a thread."""
    from scapy.sendrecv import sniff

    def route(pkt) -> None:
        codec = codecs.get(pkt.sniffed_on)
        if codec is not None:
            codec.feed(pkt)

    logger.info("Sniffing live V2G on %s", ", ".join(codecs))
    sniff(iface=list(codecs), prn=route, filter=_BPF, store=False)


def flush_every(codecs: list[V2gCodec], stop: threading.Event) -> None:
    """Flush packet rows every ``FLUSH_INTERVAL_S`` until ``stop``, then once more."""
    while not stop.wait(FLUSH_INTERVAL_S):
        for codec in codecs:
            codec.flush()
    for codec in codecs:
        codec.flush()


def decode_stream_into(codec: V2gCodec, source=None) -> None:
    """Decode a pcap byte stream (default ``sys.stdin.buffer``), stamping each frame
    at arrival — the network analog of ``candump | cantools decode``."""
    import sys

    from scapy.utils import PcapReader

    stream = source if source is not None else sys.stdin.buffer
    try:
        with PcapReader(stream) as reader:
            for pkt in reader:
                pkt.time = time.time()
                codec.feed(pkt)
    except (BrokenPipeError, EOFError):
        pass  # producer closed the pipe — normal end of stream
    except Exception:
        logger.exception("V2G stdin decode stopped on error")
    codec.flush()
    logger.info("Stream ended: %d V2G messages decoded", codec.stats.messages)


def _init_standalone(prefix: str) -> zelos_sdk.TraceSource | None:
    check_prefix(prefix)
    source = zelos_sdk.init_global_source(prefix or LOG_SOURCE_NAME)
    zelos_sdk.init(name=DEFAULT_PREFIX)
    logging.getLogger().addHandler(TraceLoggingHandler(source))
    return source if prefix else None


def run_live(
    iface: str | None = None, replay: str | Path | None = None, prefix: str = DEFAULT_PREFIX
) -> None:
    """Standalone (CLI) live runner: sniff ``iface`` (comma-separated) or replay a file."""
    shared = _init_standalone(prefix)
    options = PacketOptions()
    if replay:
        branch = Branch(branch_name(Path(replay).stem))
        replay_into(make_codec(prefix, branch, options, source=shared), replay)
        return
    ifaces = [s.strip() for s in (iface or "").split(",") if s.strip()]
    codecs = {
        i: make_codec(prefix, Branch(branch_name(i), i), options, source=shared) for i in ifaces
    }
    stop = threading.Event()
    threading.Thread(target=flush_every, args=(list(codecs.values()), stop), daemon=True).start()
    try:
        sniff_into(codecs)
    finally:
        stop.set()
        for codec in codecs.values():
            codec.flush()


def run_decode(prefix: str = DEFAULT_PREFIX, name: str = "stdin") -> None:
    """Standalone (CLI) stdin decoder."""
    shared = _init_standalone(prefix)
    codec = make_codec(prefix, Branch(branch_name(name)), PacketOptions(), source=shared)
    stop = threading.Event()
    threading.Thread(target=flush_every, args=([codec], stop), daemon=True).start()
    try:
        decode_stream_into(codec)
    finally:
        stop.set()
