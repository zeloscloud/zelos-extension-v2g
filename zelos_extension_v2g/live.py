"""Live V2G capture (and pcap replay) -> live Zelos TraceSource.

``scapy.sniff`` feeds frames to the incremental :class:`V2gStreamDecoder`, whose
records are emitted through the same :class:`V2gCodec` the offline converter uses
(here with the default namespace, so rows stream live to the agent). Use ``iface``
for a real bridged green-PHY interface, or ``replay`` for a pcap/pcapng — the same
code path, which is how we test without hardware.

``sniff_into`` assumes the SDK is already initialized (used by the extension's
app-mode in a background thread); ``run_live`` is the standalone CLI entry.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import zelos_sdk
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .codec import V2gCodec
from .pcap import SlacFrame
from .stream import V2gStreamDecoder

logger = logging.getLogger(__name__)

# Capture filter: IPv6 (SDP/V2GTP) + HomePlug AV (SLAC).
_BPF = "ip6 or ether proto 0x88e1"


def _build_decoder(codec: V2gCodec, retime=lambda ts: ts) -> V2gStreamDecoder:
    """Wire a stream decoder to a codec: each frame is decoded and emitted as it
    arrives — the same per-record path the offline converter uses, so live and trace
    modes produce identical rows.

    ``retime`` maps each record's timestamp before emit (identity for live capture;
    arrival-time for replay, so a replayed pcap appears in the live view).
    """

    def on_slac(f: SlacFrame) -> None:
        f.ts = retime(f.ts)
        codec.emit_slac(f)

    def on_sdp(f) -> None:
        f.ts = retime(f.ts)
        codec.emit_sdp(f)

    def on_message(m) -> None:
        m.ts = retime(m.ts)
        codec.emit_message(m)

    return V2gStreamDecoder(on_slac=on_slac, on_sdp=on_sdp, on_message=on_message)


def _replay_into(codec: V2gCodec, path: str, realtime: bool) -> None:
    """Replay a capture into ``codec``'s live source.

    ``realtime`` (default): release each frame at its real offset from the first —
    i.e. honor the capture's inter-frame deltas — and stamp it at arrival, so the
    session plays out in the live view over its true duration (like ``tcpreplay``).
    Otherwise feed as fast as possible, preserving the original capture timestamps
    (used by tests and quick offline import).
    """
    from scapy.utils import PcapReader

    decoder = _build_decoder(
        codec, retime=(lambda ts: time.time()) if realtime else (lambda ts: ts)
    )
    with PcapReader(path) as reader:
        wall_start = time.time()
        first_ts: float | None = None
        for pkt in reader:
            if realtime:
                ts = float(pkt.time)
                if first_ts is None:
                    first_ts = ts
                # Sleep until this frame's real offset from the first one has elapsed.
                delay = (wall_start + (ts - first_ts)) - time.time()
                if delay > 0:
                    time.sleep(delay)
            decoder.feed_packet(pkt)
    logger.info("Replay complete: %d V2G messages streamed", decoder.message_count)


def sniff_into(
    codec: V2gCodec,
    iface: str | None = None,
    replay: str | Path | None = None,
    realtime: bool = True,
) -> None:
    """Stream frames into ``codec``'s live source. Assumes the SDK is initialized.

    ``iface`` may be a single name or a comma-separated list. ``replay`` reads a
    pcap/pcapng through the identical callback path (no interface/root needed); with
    ``realtime`` the replay is paced by the capture's inter-frame deltas and stamped at
    arrival, so it appears live exactly as it happened on the wire.
    """
    try:
        if replay:
            logger.info(
                "Replaying %s as a live V2G stream%s",
                replay,
                " (real-time)" if realtime else " (fast)",
            )
            _replay_into(codec, str(replay), realtime)
        else:
            from scapy.sendrecv import sniff

            decoder = _build_decoder(codec)  # live socket already stamps real arrival time
            ifaces: str | list[str] | None = iface
            if iface and "," in iface:
                ifaces = [s.strip() for s in iface.split(",")]
            logger.info("Sniffing live V2G on %s", ifaces or "(default interface)")
            sniff(iface=ifaces, prn=decoder.feed_packet, filter=_BPF, store=False)
    except Exception:
        logger.exception("V2G live capture stopped on error")


def run_live(
    iface: str | None = None,
    replay: str | Path | None = None,
    source_name: str = "v2g",
) -> None:
    """Standalone (CLI) live runner: initialize the SDK, then sniff until interrupted."""
    zelos_sdk.init(name="v2g")
    logging.getLogger().addHandler(TraceLoggingHandler("v2g_logger"))
    sniff_into(V2gCodec(source_name=source_name), iface=iface, replay=replay)
