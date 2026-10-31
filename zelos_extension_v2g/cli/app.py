"""Agent (app) mode runner: expose actions and keep the process alive."""

from __future__ import annotations

import logging
import signal
import threading
from types import FrameType

import zelos_sdk
from zelos_sdk.extensions import load_config
from zelos_sdk.hooks.logging import TraceLoggingHandler

from ..codec import V2gCodec
from ..extension import V2gConverter
from ..live import sniff_into

logger = logging.getLogger(__name__)


def run_app_mode() -> None:
    """Run the extension in agent mode: host the Convert Pcap action, and — when an
    ``interface`` or ``replay_pcap`` is configured — also capture live and stream it."""
    config = load_config()
    logging.getLogger().setLevel(config.get("log_level") or "INFO")
    converter = V2gConverter(config)

    iface = config.get("interface") or None
    replay = config.get("replay_pcap") or None
    codec = V2gCodec(source_name=config.get("source_name") or "v2g") if (iface or replay) else None

    zelos_sdk.actions_registry.register(converter)
    zelos_sdk.init(name="V2G", actions=True)

    handler = TraceLoggingHandler("v2g_logger")
    logging.getLogger().addHandler(handler)

    def shutdown_handler(signum: int, frame: FrameType | None) -> None:
        logger.info("Shutting down...")
        converter.stop()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    if codec is not None:
        # Sniff on a background thread; the main thread keeps serving actions.
        threading.Thread(
            target=sniff_into,
            args=(codec,),
            kwargs={"iface": iface, "replay": replay},
            daemon=True,
            name="v2g-live",
        ).start()
        logger.info("V2G live capture started (interface=%s, replay=%s)", iface, replay)

    logger.info("Starting V2G extension")
    converter.start()
    converter.run()
