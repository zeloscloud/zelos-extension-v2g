"""V2G converter action host.

The extension is offline/converter-first: when launched by the agent it idles and
exposes a "Convert Pcap" action. The same conversion is available headless via the
``convert`` CLI subcommand.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import zelos_sdk

from .converter import convert_v2g_pcap, resolve_trz_output

logger = logging.getLogger(__name__)


class V2gConverter:
    """Hosts the interactive actions and keeps the extension process alive."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.running = False

    def start(self) -> None:
        logger.info("V2G converter ready (idle; use the Convert Pcap action)")
        self.running = True

    def stop(self) -> None:
        logger.info("Stopping V2G converter")
        self.running = False

    def run(self) -> None:
        """Idle loop — the converter is action-driven, not a polling source."""
        while self.running:
            time.sleep(0.5)

    @zelos_sdk.action("Convert Pcap", "Convert an ISO 15118 / DIN 70121 V2G pcap to a Zelos trace")
    @zelos_sdk.action.text(
        "input_path",
        title="Input pcap",
        description="Path to a V2G capture (.pcap)",
        widget="file-picker",
    )
    @zelos_sdk.action.text(
        "output_path",
        required=False,
        default="",
        title="Output .trz",
        description="Optional; defaults to the input name with a .trz extension",
        placeholder="e.g. /path/to/session.trz",
    )
    @zelos_sdk.action.boolean(
        "overwrite", required=False, default=False, title="Overwrite if exists", widget="toggle"
    )
    def convert_pcap(
        self, input_path: str, output_path: str = "", overwrite: bool = False
    ) -> dict[str, Any]:
        """Convert a V2G pcap to .trz and return conversion statistics."""
        try:
            input_file = Path(input_path).expanduser().resolve()
            if not input_file.exists():
                return {"status": "error", "message": f"Input file not found: {input_file}"}
            output = Path(output_path).expanduser().resolve() if output_path else None
            output_file = resolve_trz_output(input_file, output, overwrite)
            stats = convert_v2g_pcap(input_file, output_file)
            return {
                "status": "success",
                "input_file": str(input_file),
                "output_file": str(output_file),
                **stats.to_dict(),
            }
        except (FileNotFoundError, FileExistsError, ValueError) as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001 - surface any failure to the action caller
            logger.exception("Conversion failed")
            return {"status": "error", "message": f"Conversion failed: {e}"}

    @zelos_sdk.action("Get Status", "Extension status")
    def get_status(self) -> dict[str, Any]:
        return {"running": self.running}
