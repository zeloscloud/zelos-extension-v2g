"""Agent (app) mode: capture every configured interface (or replay a file) and
host the actions until SIGTERM."""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path

import zelos_sdk
from zelos_sdk.extensions import load_config
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .. import ACTION_PREFIX
from .. import actions as v2g_actions
from ..config import (
    DEFAULT_PREFIX,
    LOG_SOURCE_NAME,
    Branch,
    ConfigError,
    branch_name,
    check_prefix,
    database_files,
    make_codec,
    packet_options,
    parse_interfaces,
)
from ..live import flush_every, replay_into, sniff_into

logger = logging.getLogger(__name__)


def run_app_mode() -> None:
    config = load_config()
    advanced = config.get("advanced") or {}
    logging.getLogger().setLevel(advanced.get("log_level") or "INFO")
    replay = advanced.get("replay_pcap") or None
    try:
        prefix = check_prefix(advanced.get("prefix", DEFAULT_PREFIX))
        # A replay file replaces the interface list; its branch is the file stem.
        if replay:
            replay = str(Path(replay).expanduser())
            if not Path(replay).is_file():
                raise ConfigError(f"Replay file not found: {replay}")
            branches = [Branch(branch_name(Path(replay).stem))]
        else:
            branches = parse_interfaces(config, prefix)
        dbcs = database_files(advanced.get("database_files") or []) if replay else []
    except ConfigError as e:
        logger.error("V2G configuration is invalid: %s", e)
        sys.exit(1)

    # Actions and the shared prefix source come up BEFORE init: init advertises the
    # actions, and returns this same global source rather than a second one.
    v2g_actions.CONFIGURED_INTERFACES[:] = [b.interface for b in branches if b.interface]
    v2g_actions.register_actions(zelos_sdk.actions_registry)
    global_source = zelos_sdk.init_global_source(prefix or LOG_SOURCE_NAME)
    shared = global_source if prefix else None
    options = packet_options(advanced)
    promisc = bool(advanced.get("promiscuous", True))
    v2g_actions.PROMISCUOUS = promisc
    # A replayed file decodes its SocketCAN frames like convert does; live sniffs do not.
    codecs = {
        b.interface or b.name: make_codec(
            prefix,
            b,
            options,
            source=shared,
            can=bool(replay),
            dbcs=dbcs,
        )
        for b in branches
    }
    zelos_sdk.init(name=ACTION_PREFIX, actions=True)
    logging.getLogger().addHandler(TraceLoggingHandler(global_source))

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    sniffers, workers = [], []
    if replay:
        (codec,) = codecs.values()
        # Daemon: observes `stop`, and shutdown joins it with a bound.
        worker = threading.Thread(target=replay_into, args=(codec, replay, True, stop), daemon=True)
        worker.start()
        workers.append(worker)
        logger.info("V2G replay started: %s", branches[0].name)
    elif codecs:
        sniffers, failed = sniff_into(codecs, promisc)
        if len(failed) == len(codecs):
            logger.error("No interface could be captured (%s); stopping", ", ".join(failed))
            sys.exit(1)
        up = [b.name for b in branches if b.interface not in failed]
        logger.info("V2G capture started: %s", ", ".join(up))
    else:
        logger.info("No interfaces configured; serving actions only")

    # Returns on SIGTERM, after stopping the captures and a final flush.
    flush_every(list(codecs.values()), stop, sniffers=sniffers, workers=workers)
    logger.info("V2G extension stopped")
