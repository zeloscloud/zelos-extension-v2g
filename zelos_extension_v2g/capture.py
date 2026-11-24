"""Per-interface capture lifecycle, config parsing, and permission remediation.

One :class:`CaptureSession` per live interface, each backed by a
``zelos_packet.PacketCapture`` running in the ``zelos-packet-helper`` process:
the helper holds whatever privilege the open needs, drops it before it reads a
byte, and streams decoded rows straight to the agent over its own SDK
connection. Nothing passes through this process.

Where rows land is decided by :func:`trace_layout`, and nowhere else.
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import decode, pkg
from .constants import BUFFER_SIZE, RESERVED_NAMES, name_error
from .decode import ConfigError, V2gConfig

logger = logging.getLogger(__name__)

#: Catalog path separators, as a fallback for `zelos_packet.sanitize_name`:
#: a VLAN interface is literally named `eth0.100`.
_PATH_SEPARATORS = re.compile(r"[.:@/\s]+")

#: `zelos_packet.CaptureStats` getters reported by `get_status`.
STATS_FIELDS = (
    "packets_read",
    "bytes_read",
    "packets_truncated",
    "kernel_drops",
    "packets_dropped_agent",
    "decode_stall_ms",
    "read_errors",
)


class CaptureDeniedError(RuntimeError):
    """The OS refused a capture handle. Carries copy-pasteable remediation."""

    def __init__(self, message: str, remediation: str) -> None:
        super().__init__(message)
        self.remediation = remediation


@dataclass(frozen=True)
class InterfaceConfig:
    """One live `interfaces[]` entry, with every default already applied."""

    interface: str
    name: str


def sanitize_capture_name(raw: str) -> str:
    """Make `raw` safe as an event-name prefix, by the package's own rule."""
    native = pkg.sanitize_name(raw)
    if native is not None:
        return native
    cleaned = _PATH_SEPARATORS.sub("_", raw.strip()).strip("_")
    return cleaned or "capture"


def trace_layout(prefix: str, capture: str) -> tuple[str, str]:
    """(trace source, event-name prefix) of one capture's rows.

    Rows land at `<prefix>/<capture>/{packets,stats,slac,sdp,v2gtp,<Message>}`,
    SocketCAN frames at `<prefix>/<capture>/can/<iface>`. Live capture, replay
    and conversion all take their names from here: the tree has one shape.
    """
    return prefix, sanitize_capture_name(capture)


def parse_interfaces(config: dict) -> list[InterfaceConfig]:
    """Turn the `interfaces` array into :class:`InterfaceConfig` values.

    Defaults are applied here as well as in the JSON Schema, so CLI callers,
    which never go through `load_config`, get identical behaviour.

    Raises:
        ConfigError: on a missing interface, a bad name, or a duplicate name.
        Duplicates are a hard error rather than a silent rename: the sessions
        share one trace source, and event registration there is strict-create.
    """
    entries = config.get("interfaces") or []
    if not isinstance(entries, list):
        raise ConfigError("'interfaces' must be a list")

    parsed: list[InterfaceConfig] = []
    seen: dict[str, str] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"interfaces[{index}] must be an object")
        interface = str(entry.get("interface") or "").strip()
        if not interface:
            raise ConfigError(
                f"interfaces[{index}] is missing 'interface'. Run the 'List Interfaces' "
                "action to see the interfaces on the machine running the agent."
            )

        raw_name = str(entry.get("name") or "").strip()
        if error := name_error(raw_name, "interface Name", RESERVED_NAMES):
            raise ConfigError(error)
        name = sanitize_capture_name(raw_name or interface)
        if name in seen:
            raise ConfigError(
                f"Duplicate interface name {name!r} (interfaces {seen[name]!r} and "
                f"{interface!r}). Give each entry a unique 'name'."
            )
        seen[name] = interface
        parsed.append(InterfaceConfig(interface=interface, name=name))
    return parsed


# ─── Permission remediation ─────────────────────────────────────────────────

_REPLAY_HINT = (
    "No capture rights on this machine? Set 'Replay PCAP File' in the extension\n"
    "config to decode a .pcap/.pcapng instead; that path opens no capture handle\n"
    "and needs no privileges."
)


def builtin_grant_instructions(*, system: str | None = None, executable: str | None = None) -> str:
    """Capture-privilege instructions per platform, usable even when the
    package cannot be imported. `executable` is named outright: the grant runs
    `zelos_packet`, so it must be the interpreter this extension runs under."""
    system = system or platform.system()
    executable = executable or sys.executable or "python3"
    if system in ("Linux", "Darwin"):
        body = f"""
Live capture needs a one-time grant on this machine:

    sudo {executable} -m zelos_packet install-helper

Then log out and back in, and restart the agent: a session's groups are fixed
at login. Check the grant with:

    {executable} -m zelos_packet status
"""
    elif system == "Windows":
        body = f"""
Live capture needs Npcap (free, https://npcap.com), installed with the default
options. Check it with:

    {executable} -m zelos_packet status
"""
    else:
        body = f"""
zelos-packet has no live capture backend for {system!r}; it captures on Linux,
macOS and Windows.
"""
    return f"{body.strip()}\n\n{_REPLAY_HINT}"


def capture_grant_instructions(*, system: str | None = None) -> str:
    """Prefers ``zelos_packet.permission_remediation()``: that package opens the
    handle, so its text is authoritative. Falls back to the built-in text."""
    if (system or platform.system()) == platform.system():
        native = pkg.permission_remediation().strip()
        if native:
            return f"{native}\n\n{_REPLAY_HINT}"
    return builtin_grant_instructions(system=system)


def remediation_text(interface: str) -> str:
    return (
        f"Permission denied opening a capture handle on {interface!r}.\n\n"
        + capture_grant_instructions()
    )


def _diagnosis(exc: BaseException) -> str:
    """The native error's first paragraph: what went wrong, not how to fix it."""
    return str(exc).split("\n\n", 1)[0].strip()


# ─── Trace sources ──────────────────────────────────────────────────────────

#: The live namespace's shared source, built on first use: ONE object, not one
#: per decoder. Two `TraceSource`s under one name both register, and the query
#: layer then keeps only the newest, silently hiding the other's rows.
_live_sources: dict[str, Any] = {}

#: The running replay's `PacketDecoder`, by name, for `get_status`.
REPLAYS: dict[str, Any] = {}


def make_trace_source(source_name: str, namespace: Any = None, *, cached: bool = True) -> Any:
    """The source every decoder in this process writes into, by name.

    `namespace` of None is the global namespace `zelos_sdk.init()` set up. A
    conversion passes its own namespace and gets its own source. `cached`
    picks `TraceSourceCache` (live: last-value navigation) over a plain
    `TraceSource` (conversion: the only type the native sink batch-emits to).
    """
    import zelos_sdk

    factory = zelos_sdk.TraceSourceCache if cached else zelos_sdk.TraceSource
    if namespace is not None:
        return factory(source_name, namespace=namespace)
    if source_name not in _live_sources:
        _live_sources[source_name] = factory(source_name, namespace=None)
    return _live_sources[source_name]


# ─── Capture session ────────────────────────────────────────────────────────


@dataclass
class CaptureSession:
    """Lifecycle wrapper around one ``zelos_packet.PacketCapture``."""

    config: InterfaceConfig
    prefix: str
    promiscuous: bool = True
    v2g: V2gConfig = V2gConfig()
    _capture: Any = field(default=None, init=False, repr=False)

    @property
    def name(self) -> str:
        return self.config.name

    def capture_kwargs(self) -> dict[str, Any]:
        """Arguments handed to ``PacketCapture``. Split out so tests can assert
        them without constructing anything.

        No capture filter: the decoder reads SLAC (EtherType 0x88E1), SDP and
        V2G over either IP version, and TLS secrets disclosed in a UDP datagram
        on any port. The narrowest filter that loses none of it would drop only
        non-IP chatter, and an Ethernet expression has no meaning on a SocketCAN
        interface.
        The agent's own traffic is excluded by the package's default, derived
        from the agent URL.
        """
        source_name, name = trace_layout(self.prefix, self.config.name)
        return {
            "interface": self.config.interface,
            "name": name,
            "source_name": source_name,
            "snaplen": 0,
            "promiscuous": self.promiscuous,
            "buffer_bytes": BUFFER_SIZE,
            **self.v2g.kwargs(),
        }

    def start(self) -> None:
        """Construct the capture and begin emitting. `zelos_sdk.init()` must
        already have run. A privilege failure surfaces here with remediation."""
        decode.require()
        kwargs = self.capture_kwargs()
        try:
            self._capture = pkg.module().PacketCapture(**kwargs)
            self._capture.start()
        except Exception as exc:
            self._capture = None
            if pkg.is_permission_error(exc):
                raise CaptureDeniedError(
                    f"Capture on {self.config.interface!r} was denied: {_diagnosis(exc)}",
                    remediation_text(self.config.interface),
                ) from exc
            if type(exc).__name__ == "InterfaceNotFoundError":
                raise ConfigError(
                    f"Interface {self.config.interface!r} was not found on this machine. Run "
                    "the 'List Interfaces' action to see the interfaces it has."
                ) from exc
            raise
        logger.info(
            "Capturing V2G on %s into %s/%s (promiscuous=%s, tls_keylog=%s)",
            self.config.interface,
            kwargs["source_name"],
            kwargs["name"],
            self.promiscuous,
            self.v2g.tls_keylog or "-",
        )

    def status(self) -> dict[str, Any]:
        """Read-loop counters plus the V2G counters, or a not-started marker."""
        cap = self._capture
        if cap is None:
            return {"interface": self.config.interface, "name": self.name, "running": False}
        stats = cap.stats()
        return {
            "interface": self.config.interface,
            "name": self.name,
            "running": bool(getattr(cap, "is_active", True)),
            "error": getattr(cap, "error", None),
            **{f: getattr(stats, f, None) for f in STATS_FIELDS},
            **decode.counters(cap.metrics()),
        }

    def failure(self) -> str | None:
        """Why a started capture is no longer running, or None while it is."""
        cap = self._capture
        if cap is None or getattr(cap, "is_active", True):
            return None
        return getattr(cap, "error", None) or "the capture helper exited"

    def stop(self) -> None:
        """``PacketCapture.stop()`` is bounded (~3s): it signals the helper,
        which drains and hands everything to the agent, then reaps it."""
        if self._capture is None:
            return
        ended = self.failure()
        try:
            self._capture.stop()
        except Exception:
            # An ended capture re-raises the failure already reported.
            if not ended:
                logger.exception("Error stopping capture on %s", self.config.interface)
        self._capture = None
        logger.info("Stopped capture on %s", self.config.interface)


# ─── Interfaces, replay, permission probe ───────────────────────────────────


def list_interfaces() -> list[dict[str, Any]]:
    """Enumerate NICs on the machine running the agent."""
    return [
        {
            "name": getattr(iface, "name", str(iface)),
            "is_up": getattr(iface, "is_up", None),
            "is_loopback": getattr(iface, "is_loopback", None),
            "addresses": list(getattr(iface, "addresses", []) or []),
            # Windows: "Ethernet 5 (Intel(R) ...)" for a `\Device\NPF_{GUID}` name.
            "description": getattr(iface, "description", None),
        }
        for iface in pkg.module().list_interfaces()
    ]


def make_decoder(
    capture: str,
    prefix: str,
    *,
    namespace: Any = None,
    cached: bool = True,
    v2g: V2gConfig = V2gConfig(),
) -> Any:
    """A ``PacketDecoder`` emitting into `namespace` at `trace_layout(prefix, capture)`.

    Shared by replay (global namespace, streaming to an agent) and conversion
    (its own namespace, writing a file), so the two cannot drift on naming or
    constructor keywords.
    """
    decode.require()
    source_name, name = trace_layout(prefix, capture)
    return pkg.module().PacketDecoder(
        name=name,
        source=make_trace_source(source_name, namespace, cached=cached),
        **v2g.kwargs(),
    )


def replay_pcap(
    path: str | Path,
    *,
    name: str,
    prefix: str,
    v2g: V2gConfig = V2gConfig(),
) -> dict[str, Any]:
    """Decode a pcap/pcapng into the *live* trace namespace. No privileges required.

    Paced at the capture's own rate and shifted so the first frame lands at now.
    """
    pcap = Path(path).expanduser()
    if not pcap.exists():
        raise ConfigError(f"Capture file not found: {pcap}")
    logger.info("Replaying %s into %s/%s", pcap, *trace_layout(prefix, name))
    decoder = REPLAYS[name] = make_decoder(name, prefix, v2g=v2g)
    try:
        count = decoder.convert_file(str(pcap), realtime=True)
        decoder.flush()
    finally:
        REPLAYS.pop(name, None)
    logger.info("Replay of %s complete: %d packets", pcap.name, count)
    return {"file": str(pcap), "packets": count}


def probe_permissions(interface: str | None = None) -> dict[str, Any]:
    """Report whether live capture would work, from `zelos_packet status`,
    without opening a handle. Every failure carries remediation."""
    system = platform.system()
    supported = (
        pkg.capture_supported() if pkg.available() else system in ("Linux", "Darwin", "Windows")
    )

    def denied(reason: str, target: str | None = None, remediation: str | None = None) -> dict:
        return {
            "supported": supported,
            "can_capture": False,
            "platform": system,
            "interface": target or "",
            "reason": reason,
            "remediation": remediation if remediation is not None else capture_grant_instructions(),
        }

    if not pkg.available():
        return denied(pkg.skip_reason(), interface)
    if not decode.supported():
        try:
            decode.require()
        except RuntimeError as exc:
            return denied(str(exc), interface, remediation="")

    target = interface
    candidates = list_interfaces()
    if target and target not in {i["name"] for i in candidates}:
        return denied(f"Interface {target!r} was not found on this machine.", target, "")
    if not target:
        pool = [i for i in candidates if i["is_up"] and not i["is_loopback"]] or candidates
        if not pool:
            return denied("No network interfaces were reported by zelos-packet")
        target = str(pool[0]["name"])

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "zelos_packet", "status"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return denied(f"{type(exc).__name__}: {exc}", target)
    if proc.returncode != 0:
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        return denied(
            lines[-1] if lines else "zelos_packet status reported no capture privilege",
            target,
            remediation=remediation_text(target),
        )
    return {
        "supported": True,
        "can_capture": True,
        "platform": system,
        "interface": target,
        "reason": "",
        "remediation": "",
    }
