"""Free-floating V2G actions registered under ``V2G/<name>``.

Free functions (so ``choices=`` can reference a module-level callable), a shared
registry populated by ``cli/app.py`` at startup, and one global namespace rather
than per-interface action paths.

Every action is read-only: the extension listens and never sends on the link.
"""

from __future__ import annotations

import inspect
import logging
import platform
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from zelos_sdk.actions import ActionsRegistry, action

from . import capture as capture_mod
from . import decode, pkg
from .demo import DEMO_PCAP

if TYPE_CHECKING:
    from .capture import CaptureSession

logger = logging.getLogger(__name__)

#: Live capture sessions, keyed by capture name. Populated by `cli/app.py`.
CAPTURES: dict[str, CaptureSession] = {}


def _interface_choice(iface: dict[str, Any]) -> dict[str, str]:
    detail = []
    if isinstance(iface.get("is_up"), bool):
        detail.append("up" if iface["is_up"] else "down")
    if iface.get("is_loopback") is True:
        detail.append("loopback")
    addresses = iface.get("addresses") or []
    if addresses and isinstance(addresses[0], str):
        detail.append(addresses[0])
    choice = {"value": iface["name"], "detail": " · ".join(detail)}
    # Windows: "Ethernet 5 (Intel(R) ...)" reads better than \Device\NPF_{GUID}.
    if iface.get("description"):
        choice["label"] = iface["description"]
    return choice


def _interface_rank(iface: dict[str, Any]) -> tuple[int, str]:
    """Up non-loopback first, then up loopback, then down; names break ties."""
    up = iface.get("is_up") is True
    loopback = iface.get("is_loopback") is True
    return (0 if up and not loopback else 1 if up else 2, iface["name"])


def _scan_interfaces(build: Callable[[list[dict[str, Any]]], dict[str, Any]]) -> dict[str, Any]:
    try:
        return build(sorted(capture_mod.list_interfaces(), key=_interface_rank))
    except pkg.PacketPackageUnavailable as exc:
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.exception("Failed to enumerate interfaces")
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}"}


def _auto_config(interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    picked = [
        i["name"] for i in interfaces if i.get("is_up") is True and i.get("is_loopback") is not True
    ]
    if not picked:
        return {"status": "error", "message": "No interface on this host is up and not loopback."}
    return {
        "status": "success",
        "config": {"interfaces": [{"interface": n} for n in picked]},
    }


@action(
    "Auto-configure",
    "A configuration that captures on every interface that is up and not loopback, "
    "for the config form's Auto-configure button. Review it, then save and start.",
    standalone=True,
    hidden=True,
    read_only=True,
)
def auto_config() -> dict[str, Any]:
    return _scan_interfaces(_auto_config)


@action(
    "List Interfaces",
    "Network interfaces on the machine running the agent, as choices for the "
    "config's 'Interface' field, which also accepts a name typed by hand.",
    standalone=True,
    hidden=True,
    read_only=True,
)
def list_interfaces() -> dict[str, Any]:
    return _scan_interfaces(
        lambda interfaces: {
            "status": "success",
            "choices": [_interface_choice(i) for i in interfaces],
        }
    )


@action(
    "Check Permissions",
    "Probe whether live capture is possible on this machine and, if not, return "
    "the exact command to fix it.",
    read_only=True,
)
@action.text(
    "interface",
    title="Interface",
    description="Optional. Defaults to the first interface that is up and not loopback.",
    required=False,
    default="",
    placeholder="eth0",
)
def check_permissions(interface: str = "") -> dict[str, Any]:
    result = capture_mod.probe_permissions(interface.strip() or None)
    result["status"] = "success" if result.get("can_capture") else "error"
    result["python"] = sys.executable
    result.setdefault("platform", platform.system())
    return result


@action(
    "Get Status",
    "Every running interface's read-loop counters (packets_read, kernel_drops, "
    "decode_stall_ms) and V2G decoder counters: v2g_slac_frames, v2g_sdp_frames, "
    "v2g_messages, v2g_decoded, v2g_undecoded, v2g_framing_errors, v2g_tcp_gaps, and "
    "for sessions under TLS v2g_tls_connections, v2g_tls_decrypted, "
    "v2g_tls_secrets_seen, v2g_tls_no_secret, v2g_tls_no_handshake, "
    "v2g_tls_auth_failures. kernel_drops climbing means the kernel buffer is too "
    "small; v2g_tls_no_secret above zero means a TLS session's secrets were not "
    "disclosed.",
    read_only=True,
)
def get_status() -> dict[str, Any]:
    """No interface parameter: a select left empty fails the SDK's choice check."""
    if capture_mod.REPLAYS:
        rows = [
            {"name": n, "running": True, **decode.counters(d.metrics())}
            for n, d in sorted(capture_mod.REPLAYS.items())
        ]
        return {"status": "success", "interfaces": rows}
    if not CAPTURES:
        return {
            "status": "warning",
            "message": "No live captures are running. Configure an interface and start "
            "the extension.",
            "interfaces": [],
        }
    return {"status": "success", "interfaces": [CAPTURES[k].status() for k in sorted(CAPTURES)]}


@action(
    "Convert Pcap",
    "Convert a .pcap/.pcapng file, optionally gzip or zstd compressed, to a Zelos "
    "trace (.trz) of its charging sessions, with the capture's own timestamps. Runs "
    "without the extension running: no capture handle, no interface, no privileges, "
    "and no agent.",
    timeout=1800.0,
    standalone=True,
    read_only=True,
)
@action.text(
    "input_file",
    title="Capture file",
    description="Source .pcap or .pcapng, optionally gzip or zstd compressed",
    widget="file_path_picker",
)
@action.text(
    "output_file",
    title="Output (.trz)",
    description="Defaults to the input's name with a .trz suffix",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.text(
    "tls_keylog",
    title="TLS key log",
    description="Key log file (NSS key log format) holding the session secrets of "
    "the capture's TLS sessions",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.boolean(
    "force", title="Overwrite existing output", required=False, default=False, widget="toggle"
)
def convert_pcap(
    input_file: str, output_file: str = "", tls_keylog: str = "", force: bool = False
) -> dict[str, Any]:
    """Shares `converter.convert_pcap` with the `convert` CLI command. Failures
    raise: a standalone action's exit status is how the caller learns it failed."""
    from .converter import convert_pcap as _convert
    from .converter import resolve_output

    source = Path(input_file).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    v2g = decode.parse_v2g(tls_keylog, must_exist=True)
    destination = resolve_output(
        source, Path(output_file).expanduser() if output_file.strip() else None, overwrite=force
    )
    return _convert(source, destination, v2g=v2g)


@action(
    "Demo Capture Path",
    "Where the bundled demo capture is on the machine running the agent. Paste it "
    "into Advanced > Replay PCAP File to try the extension without a charging link.",
    standalone=True,
    read_only=True,
)
def demo_capture_path() -> dict[str, Any]:
    return {"status": "success", "path": str(DEMO_PCAP)}


def register_actions(registry: ActionsRegistry) -> list[str]:
    """Register every ``@action``-decorated free function by its bare name.

    The ``V2G/`` prefix consumers see comes from
    ``zelos_sdk.init(name="V2G", actions=True)``.
    """
    module = sys.modules[__name__]
    registered: list[str] = []
    for name, obj in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        if inspect.isfunction(obj) and hasattr(obj, "_action"):
            registry.register(obj, name=name)
            registered.append(name)
    logger.info("Registered %d V2G actions", len(registered))
    return registered
