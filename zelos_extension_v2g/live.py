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

# SLAC pairing completes at the MATCH confirmation -> emit a one-shot init summary.
# (CM_SET_KEY is local modem key-setup and can appear before SLAC even starts, so it
# is not a reliable "done" marker.)
_SLAC_DONE = {"CM_SLAC_MATCH.CNF"}
# Capture filter: IPv6 (SDP/V2GTP) + HomePlug AV (SLAC).
_BPF = "ip6 or ether proto 0x88e1"


def _build_decoder(codec: V2gCodec, retime=lambda ts: ts) -> V2gStreamDecoder:
    """Wire a stream decoder to a codec, emitting a one-shot SLAC summary on match.

    ``retime`` maps each record's timestamp before emit (identity for live capture;
    arrival-time for replay, so a replayed pcap appears in the live view).
    """
    slac_frames: list[SlacFrame] = []
    state = {"summarized": False}

    def on_slac(f: SlacFrame) -> None:
        f.ts = retime(f.ts)
        codec.emit_slac(f)
        slac_frames.append(f)
        if f.name in _SLAC_DONE and not state["summarized"]:
            codec.emit_slac_summary(slac_frames, ts=f.ts)
            state["summarized"] = True

    def on_sdp(f) -> None:
        f.ts = retime(f.ts)
        codec.emit_sdp(f)

    def on_message(m) -> None:
        m.ts = retime(m.ts)
        codec.emit_message(m)

    return V2gStreamDecoder(on_slac=on_slac, on_sdp=on_sdp, on_message=on_message)


def sniff_into(
    codec: V2gCodec,
    iface: str | None = None,
    replay: str | Path | None = None,
    realtime: bool = True,
) -> None:
    """Stream frames into ``codec``'s live source. Assumes the SDK is initialized.

    ``iface`` may be a single name or a comma-separated list. ``replay`` reads a
    pcap/pcapng through the identical callback path (no interface/root needed); with
    ``realtime`` it is stamped at arrival so the replay appears live (mirroring a
    ``tcpreplay`` onto an interface, where frames are timestamped on the wire).
    """
    from scapy.sendrecv import sniff

    retime = (lambda ts: time.time()) if (replay and realtime) else (lambda ts: ts)
    decoder = _build_decoder(codec, retime)
    try:
        if replay:
            logger.info("Replaying %s as a live V2G stream", replay)
            sniff(offline=str(replay), prn=decoder.feed_packet, store=False)
            logger.info("Replay complete: %d V2G messages streamed", decoder.message_count)
        else:
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
