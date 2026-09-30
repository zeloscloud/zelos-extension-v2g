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
        branches = (
            [Branch(branch_name(Path(replay).stem))] if replay else parse_interfaces(config, prefix)
        )
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
    codecs = {
        b.interface or b.name: make_codec(prefix, b, options, source=shared) for b in branches
    }
    zelos_sdk.init(name=ACTION_PREFIX, actions=True)
    logging.getLogger().addHandler(TraceLoggingHandler(global_source))

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    if replay:
        (codec,) = codecs.values()
        target, args = replay_into, (codec, replay, True, stop)
    else:
        target, args = sniff_into, (codecs,)
    if codecs:
        # Daemon: a sniff blocks in the kernel and cannot be woken on stop.
        threading.Thread(
            target=_log_errors(target), args=args, daemon=True, name="v2g-live"
        ).start()
        logger.info("V2G capture started: %s", ", ".join(b.name for b in branches))
    else:
        logger.info("No interfaces configured; serving actions only")

    flush_every(list(codecs.values()), stop)  # returns on SIGTERM, after a final flush
    logger.info("V2G extension stopped")


def _log_errors(fn):
    def run(*args):
        try:
            fn(*args)
        except Exception:
            logger.exception("V2G capture stopped on error (run the Check Permissions action)")

    return run
