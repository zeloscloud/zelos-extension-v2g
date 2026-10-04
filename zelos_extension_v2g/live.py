"""Live V2G capture, pcap replay, and stdin decode -> live Zelos trace.

Every path hands scapy packets to a :class:`V2gCodec` (``codec.feed``), the same
per-frame path the offline converter uses, so live and trace modes produce
identical rows. Replay and stdin re-stamp ``pkt.time`` before the feed, so V2G
events and packet rows share one timestamp.

These assume the SDK is already initialized; ``run_live`` / ``run_decode`` are
the standalone CLI entries.
"""

from __future__ import annotations

import contextlib
import logging
import platform
import signal
import threading
import time
from decimal import Decimal
from pathlib import Path

import zelos_sdk
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .codec import V2gCodec
from .config import (
    DEFAULT_PREFIX,
    LOG_SOURCE_NAME,
    Branch,
    ConfigError,
    PacketOptions,
    branch_name,
    check_prefix,
    make_codec,
    parse_interfaces,
)

logger = logging.getLogger(__name__)

# Capture filter: IPv6 (SDP/V2GTP) + HomePlug AV (SLAC).
_BPF = "ip6 or ether proto 0x88e1"

#: How often live paths push buffered packet rows (`decode_frame` has no timer).
FLUSH_INTERVAL_S = 0.5
#: Bound on waiting for a replay/stdin worker at shutdown.
_JOIN_TIMEOUT_S = 3.0

_ARPHRD_LOOPBACK = 772


def replay_into(codec: V2gCodec, path: str | Path, realtime: bool = True, stop=None) -> None:
    """Replay a capture into ``codec``.

    ``realtime``: shift every timestamp by one constant offset so the first frame
    lands at now, and release each frame when its shifted time comes (like
    ``tcpreplay``). Otherwise feed as fast as possible with the capture's own
    timestamps. ``stop`` (a ``threading.Event``) ends the replay early.
    """
    from scapy.utils import PcapReader

    stop = stop or threading.Event()
    offset: Decimal | None = None
    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if realtime:
                    if offset is None:
                        offset = Decimal(time.time_ns()) / 10**9 - pkt.time
                    pkt.time += offset  # Decimal: exact ns survive the shift
                    delay = float(pkt.time) - time.time()
                    if delay > 0 and stop.wait(delay):
                        break
                elif stop.is_set():
                    break
                codec.feed(pkt)
    except Exception:
        logger.exception("%s: replay stopped on error", codec.name)
    logger.info("Replay complete: %d V2G messages streamed", codec.stats.messages)


def _drops_outgoing(system: str, arphrd: int) -> bool:
    """Linux loopback hands AF_PACKET both copies of each frame (outgoing + incoming);
    libpcap keeps one there, so we do too. Elsewhere outgoing frames are real traffic
    (this host may be the EVCC or SECC)."""
    return system == "Linux" and arphrd == _ARPHRD_LOOPBACK


def open_capture(iface: str, promisc: bool = True):
    """A scapy listen socket on ``iface`` with the V2G filter. Raises on refusal."""
    import scapy.sendrecv  # noqa: F401 - loads the platform's capture sockets
    from scapy.config import conf
    from scapy.interfaces import resolve_iface

    try:
        arphrd = resolve_iface(iface).type
    except Exception:  # noqa: BLE001 - unknown here; the open below reports it
        arphrd = -1
    # On Linux, L2socket drops PACKET_OUTGOING; L2listen keeps it.
    sock = conf.L2socket if _drops_outgoing(platform.system(), arphrd) else conf.L2listen
    return sock(iface=iface, promisc=promisc, filter=_BPF)


def sniff_into(codecs: dict[str, V2gCodec], promisc: bool = True) -> tuple[list, list[str]]:
    """Open one capture per interface in ``codecs`` (keyed by interface) and sniff each
    on its own thread into its codec. An interface that fails to open is logged and
    skipped; the others keep capturing.

    Returns ``(sniffers, failed interfaces)``; pass the sniffers to :func:`flush_every`.
    """
    from scapy.sendrecv import AsyncSniffer

    sniffers, failed = [], []
    for iface, codec in codecs.items():
        try:
            sock = open_capture(iface, promisc)
        except Exception as exc:  # noqa: BLE001 - any refusal skips just this interface
            logger.error("Cannot capture on %s: %s: %s", iface, type(exc).__name__, exc)
            failed.append(iface)
            continue
        sniffer = AsyncSniffer(opened_socket=sock, prn=codec.feed, store=False)
        sniffer.start()
        sniffers.append(sniffer)
        logger.info("Sniffing live V2G on %s%s", iface, "" if promisc else " (not promiscuous)")
    return sniffers, failed


def flush_every(codecs: list[V2gCodec], stop: threading.Event, sniffers=(), workers=()) -> None:
    """Flush packet rows every ``FLUSH_INTERVAL_S`` until ``stop``. Then stop the
    ``sniffers`` and join the ``workers`` (replay/stdin threads, bounded) so no frame
    lands after the final flush, flush once more and log per-branch frame errors."""
    while not stop.wait(FLUSH_INTERVAL_S):
        for codec in codecs:
            codec.flush()
    for sniffer in sniffers:
        with contextlib.suppress(Exception):  # already ended
            sniffer.stop()
        sniffer.kwargs["opened_socket"].close()
    for worker in workers:
        worker.join(_JOIN_TIMEOUT_S)
    for codec in codecs:
        codec.flush()
        codec.report_errors()


def decode_stream_into(codec: V2gCodec, source=None) -> None:
    """Decode a pcap byte stream (default ``sys.stdin.buffer``), stamping each frame
    at arrival — the network analog of ``candump | cantools decode``."""
    import sys

    from scapy.utils import PcapReader

    stream = source if source is not None else sys.stdin.buffer
    try:
        with PcapReader(stream) as reader:
            for pkt in reader:
                pkt.time = Decimal(time.time_ns()) / 10**9
                codec.feed(pkt)
    except (BrokenPipeError, EOFError):
        pass  # producer closed the pipe — normal end of stream
    except Exception:
        logger.exception("%s: stdin decode stopped on error", codec.name)
    logger.info("Stream ended: %d V2G messages decoded", codec.stats.messages)


def _init_standalone(prefix: str) -> tuple[zelos_sdk.TraceSource | None, threading.Event]:
    """SDK up with logs traced; returns the shared source and a stop event set on
    SIGINT / SIGTERM."""
    try:
        check_prefix(prefix)
    except ConfigError as e:
        raise SystemExit(f"Error: {e}") from e
    source = zelos_sdk.init_global_source(prefix or LOG_SOURCE_NAME)
    zelos_sdk.init(name=DEFAULT_PREFIX)
    logging.getLogger().addHandler(TraceLoggingHandler(source))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    return (source if prefix else None), stop


def _worker(stop: threading.Event, fn, *args) -> threading.Thread:
    """``fn(*args)`` on a daemon thread that sets ``stop`` when it returns."""

    def run() -> None:
        try:
            fn(*args)
        finally:
            stop.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def run_live(
    iface: str | None = None, replay: str | Path | None = None, prefix: str = DEFAULT_PREFIX
) -> None:
    """Standalone (CLI) live runner: sniff ``iface`` (comma-separated) or replay a file."""
    ifaces = [s.strip() for s in (iface or "").split(",") if s.strip()]
    try:
        branches = parse_interfaces({"interfaces": [{"interface": i} for i in ifaces]}, prefix)
    except ConfigError as e:
        raise SystemExit(f"Error: {e}") from e
    shared, stop = _init_standalone(prefix)
    options = PacketOptions()
    if replay:
        branch = Branch(branch_name(Path(replay).stem))
        codec = make_codec(prefix, branch, options, source=shared, can=True)
        worker = _worker(stop, replay_into, codec, replay, True, stop)
        flush_every([codec], stop, workers=[worker])
        return
    codecs = {b.interface: make_codec(prefix, b, options, source=shared) for b in branches}
    sniffers, failed = sniff_into(codecs)
    if len(failed) == len(codecs):
        raise SystemExit("no interface could be captured")
    flush_every(list(codecs.values()), stop, sniffers=sniffers)  # until Ctrl-C


def run_decode(
    prefix: str = DEFAULT_PREFIX, name: str = "stdin", dbcs: tuple[str, ...] = ()
) -> None:
    """Standalone (CLI) stdin decoder; SocketCAN frames decode like convert."""
    shared, stop = _init_standalone(prefix)
    branch = Branch(branch_name(name))
    codec = make_codec(prefix, branch, PacketOptions(), source=shared, can=True, dbcs=dbcs)
    flush_every([codec], stop, workers=[_worker(stop, decode_stream_into, codec)])
