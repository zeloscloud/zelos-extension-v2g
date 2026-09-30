"""Feed SocketCAN frames into zelos-can's Rust ``CanDecoder``.

CAN frame cracking (raw logging + DBC signal decode, value tables, multiplexing)
lives in the shared ``zelos-can`` package; this is only the glue that nests a
capture's CAN rows under its V2G branch: ``<name>/CAN/Frame`` (raw,
``zelos.can.frame.v1``) and ``<name>/CAN/<message>`` (with a DBC), on the same
source object as that branch's V2G events.
"""

from __future__ import annotations

import zelos_sdk
from zelos_can import CanDecoder

from .socketcan import CanFrame


class CanIngest:
    """A ``zelos-can`` ``CanDecoder`` writing into ``source`` under ``<name>/CAN``."""

    def __init__(self, source: zelos_sdk.TraceSource, name: str, dbc: str | None = None) -> None:
        kwargs: dict = {
            # The branch's own source object: a second same-named source would
            # register separately and the query layer keeps only the newest.
            "source": source,
            "raw_source": source,
            "event_prefix": f"{name}/CAN",
            "raw_event_name": f"{name}/CAN/Frame",
            # Keep raw frames even when a DBC is decoding signals.
            "log_raw_frames": True,
            "timestamp_mode": "absolute",
        }
        if dbc is not None:
            kwargs["database_file"] = str(dbc)
            kwargs["emit_schemas_on_init"] = True
        # No DBC -> raw-frame-only decoder.
        self._decoder = CanDecoder(**kwargs)
        self.dbc = str(dbc) if dbc else None

    def emit(self, f: CanFrame) -> None:
        self._decoder.decode_frame(
            arbitration_id=f.can_id,
            data=f.data,
            timestamp_ns=int(f.ts * 1e9),
            is_extended=f.extended,
            is_fd=False,
            is_remote_frame=f.remote,
        )

    def metrics(self):
        return self._decoder.metrics()
