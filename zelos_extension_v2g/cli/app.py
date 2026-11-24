"""App-config mode: how the supervisor launches us, from config.json."""

from __future__ import annotations

import contextlib
import logging
import signal
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any

import zelos_sdk
from zelos_sdk.extensions import ConfigValidationError, load_config
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .. import ACTION_PREFIX, decode
from .. import actions as v2g_actions
from ..capture import (
    CaptureDeniedError,
    CaptureSession,
    InterfaceConfig,
    parse_interfaces,
    replay_pcap,
)
from ..constants import DEFAULT_PREFIX, RESERVED_NAMES, name_error
from ..converter import capture_stem
from ..decode import ConfigError, V2gConfig, parse_v2g
from ..demo import DEMO_PCAP

logger = logging.getLogger(__name__)

#: `advanced` settings and their defaults. Everything here is global.
ADVANCED_DEFAULTS: dict[str, Any] = {
    "prefix": DEFAULT_PREFIX,
    "promiscuous": True,
    "log_level": "INFO",
}


def resolve_advanced(config: dict) -> dict:
    """Merge the `advanced` object over its defaults."""
    return {**ADVANCED_DEFAULTS, **(config.get("advanced") or {})}


def _fail(message: str) -> None:
    """Log a legible one-line reason and exit non-zero.

    The supervisor does not restart a crashed extension, so a clear final log
    line in `extension.log` is the whole user experience of a failed start.
    """
    logger.error("%s", message)
    sys.exit(1)


def _apply_log_level(advanced: dict) -> None:
    level = getattr(logging, str(advanced.get("log_level", "INFO")), None)
    if isinstance(level, int):
        logging.getLogger().setLevel(level)
    else:
        logger.warning("Invalid log level %r, using INFO", advanced.get("log_level"))
        logging.getLogger().setLevel(logging.INFO)


def resolve_output_file(file: Path | None) -> Path | None:
    if file is None:
        return None
    if str(file) == ".":
        return Path(f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.trz")
    return file


def init_sdk(prefix: str) -> None:
    """Actions, the SDK, and the log handler, in the order every entry point needs.

    The log source comes up first so startup messages land in the trace under
    `<prefix>/log`. `init_global_source` is idempotent, so `init` reuses it.
    `ACTION_PREFIX` is package-level so the live namespace and the packaged
    at-rest inventory cannot drift apart.
    """
    v2g_actions.register_actions(zelos_sdk.actions_registry)
    global_source = zelos_sdk.init_global_source(prefix)
    zelos_sdk.init(name=ACTION_PREFIX, log_level="info", actions=True)
    root = logging.getLogger()
    if not any(isinstance(h, TraceLoggingHandler) for h in root.handlers):
        # No level of its own: the Log Level setting on the root logger decides.
        root.addHandler(TraceLoggingHandler(global_source))


def _install_shutdown(stop_event: threading.Event) -> None:
    def handler(signum: int, _frame: FrameType | None) -> None:
        logger.info("Received signal %d, shutting down...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def _install_replay_shutdown() -> None:
    """Turn a supervisor Stop during a replay into an unwind, not a kill.

    Default SIGTERM handling skips every `finally`, leaving a half-written .trz.
    Raising lets the `TraceWriter` close it. A paced `convert_file` checks for
    signals every 100 ms, so the handler fires mid-file.
    """

    def handler(signum: int, _frame: FrameType | None) -> None:
        logger.info("Received signal %d, stopping replay...", signum)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def run_sessions(
    configs: list[InterfaceConfig], prefix: str, *, promiscuous: bool, v2g: V2gConfig
) -> None:
    """Start every live session, wait for shutdown, then stop them together.

    One interface that fails to open fails the whole start: the ones already
    open are stopped on the way out. A capture that ends while running is one
    ERROR line; the rest keep capturing. When the last one ends this raises,
    and the caller exits non-zero. Unwinding (rather than `os._exit`) matters:
    the SDK's atexit hook drains the trace namespace and blocks until every
    queued event is delivered.
    """
    stop_event = threading.Event()
    _install_shutdown(stop_event)
    started: list[CaptureSession] = []
    try:
        for cfg in configs:
            session = CaptureSession(cfg, prefix, promiscuous=promiscuous, v2g=v2g)
            session.start()
            started.append(session)
            v2g_actions.CAPTURES[session.name] = session
        logger.info(
            "Capturing on %d interface%s; waiting for stop", len(started), "s"[: len(started) != 1]
        )
        # Polled: on Windows a bare wait() is not interrupted by Ctrl+C, the
        # agent's stop signal, so the handler would never run.
        ended: set[str] = set()
        while not stop_event.wait(0.5):
            for session in started:
                if session.name in ended or not (reason := session.failure()):
                    continue
                ended.add(session.name)
                message = f"Capture on {session.config.interface} ended: {reason}"
                if len(ended) == len(started):
                    # Nothing left to capture: the caller logs this and exits non-zero.
                    raise RuntimeError(f"{message}. Capture has stopped on all interfaces.")
                logger.error("%s", message)
    finally:
        # Together: each stop is bounded (~3s), so the whole stop is, whatever the count.
        stops = [threading.Thread(target=session.stop) for session in started]
        for thread in stops:
            thread.start()
        for thread in stops:
            thread.join()
        v2g_actions.CAPTURES.clear()


def run_replay(
    path: Path, *, name: str, prefix: str, v2g: V2gConfig, output_file: Path | None
) -> None:
    """Replay one capture into the live namespace, once, and return when it ends.

    A Stop mid-file unwinds as `KeyboardInterrupt`, which closes the writer and
    is reported rather than raised.
    """
    _install_replay_shutdown()
    try:
        with contextlib.ExitStack() as stack:
            if output_file:
                logger.info("Recording trace to: %s", output_file)
                stack.enter_context(zelos_sdk.TraceWriter(str(output_file)))
            replay_pcap(path, name=name, prefix=prefix, v2g=v2g)
    except KeyboardInterrupt:
        logger.warning("Replay of %s stopped before it finished", path)


def run_app_mode(demo_flag: bool, file: Path | None) -> None:
    """Run from the Zelos App / supervisor configuration (no subcommand)."""
    try:
        config = load_config()
    except ConfigValidationError as exc:
        _fail("Invalid configuration: " + "; ".join(m.strip(" •") for m in exc.errors))
    advanced = resolve_advanced(config)
    _apply_log_level(advanced)
    prefix = str(advanced.get("prefix") or "").strip()
    if error := name_error(prefix, "Prefix", RESERVED_NAMES, required=True):
        _fail(error)

    if demo_flag:
        logger.info("Demo mode: replaying the bundled capture once")
        advanced["replay_pcap"] = str(DEMO_PCAP)
    replay = str(advanced.get("replay_pcap") or "").strip()

    interfaces: list[InterfaceConfig] = []
    v2g = V2gConfig()
    try:
        v2g = parse_v2g(config.get("tls_keylog"), must_exist=bool(replay))
        if not replay:
            interfaces = parse_interfaces(config)
    except ConfigError as exc:
        _fail(str(exc))
    if not replay and not interfaces:
        _fail(
            "Nothing to do: no interfaces are configured and no replay file is set. "
            "Add an interface (run the 'List Interfaces' action to see what this "
            "machine has), or set 'Replay PCAP File' to decode a capture instead."
        )

    output_file = resolve_output_file(file)
    init_sdk(prefix)
    # One legible refusal before a writer or capture exists; the CLI refuses in
    # CaptureSession.start / make_decoder.
    try:
        decode.require()
    except RuntimeError as exc:
        _fail(str(exc))
    logger.info("Trace prefix: %s", prefix)

    if replay:
        logger.info("Replay mode: decoding %s (no capture handle is opened)", replay)
        try:
            run_replay(
                Path(replay),
                name=capture_stem(Path(replay)),
                prefix=prefix,
                v2g=v2g,
                output_file=output_file,
            )
        except ConfigError as exc:
            _fail(str(exc))
        except Exception as exc:
            logger.exception("Replay failed")
            _fail(f"Replay of {replay} failed: {exc}")
        return

    try:
        with contextlib.ExitStack() as stack:
            if output_file:
                logger.info("Recording trace to: %s", output_file)
                stack.enter_context(zelos_sdk.TraceWriter(str(output_file)))
            run_sessions(
                interfaces, prefix, promiscuous=bool(advanced.get("promiscuous", True)), v2g=v2g
            )
    except CaptureDeniedError as exc:
        # Exit cleanly with the remediation: the supervisor does not restart on
        # crash, so this message is the fix.
        logger.error("%s\n\n%s", exc, exc.remediation)
        sys.exit(1)
    except (ValueError, RuntimeError) as exc:
        # A typo'd interface (ValueError) or a native capture failure
        # (RuntimeError): one legible line.
        _fail(str(exc))
