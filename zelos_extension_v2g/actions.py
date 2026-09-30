"""Free-function actions registered under ``V2G/<name>``.

Same registry pattern as the Packet extension: module-level ``@action`` functions,
registered by ``register_actions`` before ``zelos_sdk.init``. ``standalone=True``
ones also run at rest (no extension process), which is how the config form's
Auto-configure button and interface picker work before the first Start.
"""

from __future__ import annotations

import inspect
import logging
import os
import platform
import shlex
import sys
from pathlib import Path
from typing import Any

from zelos_sdk.actions import ActionsRegistry, action

logger = logging.getLogger(__name__)

#: Interfaces the running extension was configured with; set by app mode.
CONFIGURED_INTERFACES: list[str] = []


def _interfaces() -> list[dict[str, Any]]:
    """Host NICs, up non-loopback first, then up loopback, then down."""
    import zelos_packet

    found = [
        {
            "name": i.name,
            "is_up": i.is_up,
            "is_loopback": i.is_loopback,
            "addresses": list(i.addresses),
        }
        for i in zelos_packet.list_interfaces()
    ]
    return sorted(
        found,
        key=lambda i: (
            0 if i["is_up"] and not i["is_loopback"] else 1 if i["is_up"] else 2,
            i["name"],
        ),
    )


def _choice(iface: dict[str, Any]) -> dict[str, str]:
    detail = ["up" if iface["is_up"] else "down"]
    if iface["is_loopback"]:
        detail.append("loopback")
    if iface["addresses"]:
        detail.append(iface["addresses"][0])
    return {"value": iface["name"], "detail": " · ".join(detail)}


@action(
    "Auto-configure",
    "A configuration that captures on every interface that is up and not loopback, "
    "for the config form's Auto-configure button. Review it, then save and start.",
    standalone=True,
)
def auto_config() -> dict[str, Any]:
    """The app's auto-configure contract: ``config`` replaces the form's keys."""
    picked = [i["name"] for i in _interfaces() if i["is_up"] and not i["is_loopback"]]
    if not picked:
        return {"status": "error", "message": "No interface on this host is up and not loopback."}
    return {"status": "success", "config": {"interfaces": [{"interface": n} for n in picked]}}


@action(
    "List Interfaces",
    "Network interfaces on the machine running the agent, as choices for the "
    "config's 'Interface' field, which also accepts a name typed by hand.",
    standalone=True,
)
def list_interfaces() -> dict[str, Any]:
    """The app's ``action-choices`` contract: ``choices`` in the order to show."""
    return {"status": "success", "choices": [_choice(i) for i in _interfaces()]}


def _remediation(system: str) -> str:
    if system == "Darwin":
        return (
            "macOS lets only root read /dev/bpf*. Grant access once with Wireshark's "
            "ChmodBPF helper (`brew install --cask wireshark-chmodbpf`, which adds you "
            "to the access_bpf group), log out and back in, then restart the "
            "extension. Or run the agent as root."
        )
    if system == "Linux":
        # setcap needs the real file, not the venv's symlink.
        python = shlex.quote(os.path.realpath(sys.executable))
        return (
            "Grant raw-socket capture to the extension's interpreter:\n\n"
            f"    sudo setcap cap_net_raw,cap_net_admin=eip {python}\n\n"
            "then restart the extension. Or run the agent as root."
        )
    return "Live capture is supported on Linux and macOS. Use Replay PCAP File instead."


@action(
    "Check Permissions",
    "Try to open a capture on an interface and, if refused, return the exact fix.",
)
@action.text(
    "interface",
    title="Interface",
    description="Defaults to the first configured interface.",
    required=False,
    default="",
    placeholder="eth0",
)
def check_permissions(interface: str = "") -> dict[str, Any]:
    import scapy.sendrecv  # noqa: F401 - loads the platform's capture sockets
    from scapy.config import conf

    system = platform.system()
    target = interface.strip() or next(iter(CONFIGURED_INTERFACES), "")
    if not target:
        target = next((i["name"] for i in _interfaces() if i["is_up"]), "")
    result = {"interface": target, "platform": system, "python": sys.executable}
    if target not in {i["name"] for i in _interfaces()}:
        # Not a permission problem: the fix is a different name, not a grant.
        return {
            **result,
            "status": "error",
            "can_capture": False,
            "reason": f"Interface {target!r} not found. Run the List Interfaces action.",
        }
    try:
        conf.L2listen(iface=target).close()
    except Exception as exc:  # noqa: BLE001 - any refusal is the answer here
        result.update(status="error", can_capture=False, reason=f"{type(exc).__name__}: {exc}")
        # Linux raises PermissionError; macOS scapy reports every /dev/bpf refused.
        if isinstance(exc, PermissionError) or "No /dev/bpf handle" in str(exc):
            result["remediation"] = _remediation(system)
        return result
    return {**result, "status": "success", "can_capture": True}


@action(
    "Convert Pcap",
    "Convert a CAN / V2G capture (.pcap/.pcapng) to a Zelos trace (.trz). Runs "
    "without the extension running: no interface, no privileges, no agent.",
    # I/O bound over files that can be large; a ceiling, not an expectation.
    timeout=1800.0,
    standalone=True,
)
@action.text(
    "input_file",
    title="Capture file",
    description="Source .pcap or .pcapng: CAN, V2G, or both",
    widget="file_path_picker",
)
@action.text(
    "output_file",
    title="Output (.trz)",
    description="Defaults to the input file with a .trz suffix",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.boolean(
    "force", title="Overwrite existing output", required=False, default=False, widget="toggle"
)
@action.text(
    "dbc_file",
    title="CAN database (.dbc)",
    description="Optional; decode CAN frames into named signals (raw frames are always kept)",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.boolean(
    "log_packets",
    title="Log packets",
    description="Also write every frame as a packet row at '<file>/packets'",
    required=False,
    default=True,
    widget="toggle",
)
def convert_pcap(
    input_file: str,
    output_file: str = "",
    force: bool = False,
    dbc_file: str = "",
    log_packets: bool = True,
) -> dict[str, Any]:
    """Convert one capture to .trz. Failures raise: a standalone action's exit status
    is how the caller learns it failed."""
    from .converter import convert_capture, resolve_trz_output

    source = Path(input_file).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    output = Path(output_file).expanduser().resolve() if output_file.strip() else None
    dbc = Path(dbc_file).expanduser().resolve() if dbc_file.strip() else None
    destination = resolve_trz_output(source, output, force)
    stats = convert_capture(source, destination, dbc=dbc, log_packets=log_packets)
    return {
        "status": "success",
        "input_file": str(source),
        "output_file": str(destination),
        **stats.to_dict(),
    }


def register_actions(registry: ActionsRegistry) -> list[str]:
    """Register every ``@action`` function by its bare name; ``init(name="V2G")``
    supplies the ``V2G/`` prefix."""
    module = sys.modules[__name__]
    names = [
        name
        for name, obj in inspect.getmembers(module, inspect.isfunction)
        if not name.startswith("_") and hasattr(obj, "_action")
    ]
    for name in names:
        registry.register(getattr(module, name), name=name)
    return names
