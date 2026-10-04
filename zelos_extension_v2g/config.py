"""Config parsing and the per-branch codec factory shared by every entry point."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import zelos_packet
import zelos_sdk

from .codec import V2gCodec, trace_layout

logger = logging.getLogger(__name__)

DEFAULT_PREFIX = "V2G"
#: The logs' source when the prefix is cleared (with a prefix they land at `<prefix>/log`).
LOG_SOURCE_NAME = "v2g_log"


class ConfigError(ValueError):
    """A config mistake, reported by field rather than as a crash."""


@dataclass(frozen=True)
class Branch:
    """One capture target: an interface (live) or a file (replay/convert)."""

    name: str
    interface: str | None = None


@dataclass(frozen=True)
class PacketOptions:
    log_packets: bool = True
    log_frames: bool = True
    stored_frame_bytes: int | None = None


def branch_name(raw: str) -> str:
    """A catalog-safe branch name.

    The SDK allow-list first (a file stem like ``capture (1)`` carries characters no
    event name accepts), then ``zelos_packet``'s rule, so the result is exactly the
    name the packet decoder registers under.
    """
    return zelos_packet.sanitize_name(zelos_sdk.sanitize_name(raw.strip(), kind="source"))


def check_prefix(prefix: str) -> str:
    """``prefix`` unchanged, or ConfigError if it would re-nest the trace tree."""
    if prefix and zelos_sdk.sanitize_name(prefix, kind="source") != prefix:
        raise ConfigError(f"Invalid prefix {prefix!r}: use letters, digits, space, '_' or '-'.")
    return prefix


def parse_interfaces(config: dict[str, Any], prefix: str) -> list[Branch]:
    """The ``interfaces`` list as branches. Duplicate interfaces or names are a hard error."""
    entries = config.get("interfaces") or []
    branches: list[Branch] = []
    seen: dict[str, str] = {}
    for i, entry in enumerate(entries):
        interface = str((entry or {}).get("interface") or "").strip()
        if not interface:
            raise ConfigError(f"interfaces[{i}] is missing 'interface'")
        if interface in seen.values():
            raise ConfigError(f"Interface {interface!r} is listed twice; list it once.")
        name = branch_name(str(entry.get("name") or "") or interface)
        if name in seen:
            raise ConfigError(
                f"Duplicate name {name!r} (interfaces {seen[name]!r} and {interface!r}). "
                "Give each interface a unique 'name'."
            )
        if not prefix and name == LOG_SOURCE_NAME:
            raise ConfigError(f"Name {name!r} is reserved for the extension's log source.")
        seen[name] = interface
        branches.append(Branch(name, interface))
    return branches


def database_files(paths: Sequence[str | Path]) -> list[str]:
    """CAN databases, ``~``-expanded, in precedence order (later wins). Missing is an error."""
    files = [str(Path(p).expanduser()) for p in paths if str(p).strip()]
    for f in files:
        if not Path(f).is_file():
            raise ConfigError(f"CAN database not found: {f}")
    return files


def packet_options(advanced: dict[str, Any]) -> PacketOptions:
    return PacketOptions(
        log_packets=bool(advanced.get("log_packets", True)),
        log_frames=bool(advanced.get("log_frames", True)),
        stored_frame_bytes=advanced.get("stored_frame_bytes"),
    )


def make_codec(
    prefix: str,
    branch: Branch,
    options: PacketOptions,
    *,
    source: zelos_sdk.TraceSource | None = None,
    namespace: zelos_sdk.TraceNamespace | None = None,
    can: bool = False,
    dbcs: Sequence[str] = (),
) -> V2gCodec:
    """A codec for ``branch`` per :func:`trace_layout`.

    Pass ``source`` to share one prefix source across branches: two sources under one
    name register separately and the query layer keeps only the newest. ``can`` decodes
    SocketCAN frames found in a file (with ``dbcs``, in precedence order); live sniffs
    leave it off.
    """
    source_name, event_prefix = trace_layout(prefix, branch.name)
    if source is None:
        source = zelos_sdk.TraceSource(source_name, namespace=namespace)
    packets = None
    if options.log_packets:
        packets = zelos_packet.PacketDecoder(
            name=branch.name,
            source=source,
            iface=branch.interface or branch.name,
            log_frames=options.log_frames,
            stored_frame_bytes=options.stored_frame_bytes,
        )
    return V2gCodec(source, branch.name, event_prefix, packets=packets, can=can, dbcs=dbcs)
