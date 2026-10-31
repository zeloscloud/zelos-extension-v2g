"""Feed SocketCAN frames into zelos-can's Rust ``CanDecoder``.

The CAN frame cracking (raw logging + DBC signal decode, value tables,
multiplexing) lives in the shared ``zelos-can`` package. This module binds a
``CanDecoder`` to a caller-provided :class:`~zelos_sdk.TraceNamespace` and hands
it parsed frames, so CAN rows land in the same ``.trz`` as the V2G rows. With no
DBC, the decoder logs raw frames only.
"""

from __future__ import annotations

import zelos_sdk
from zelos_can import CanDecoder

from .socketcan import CanFrame


class CanIngest:
    """A ``zelos-can`` ``CanDecoder`` bound to ``namespace``.

    Emits raw ``can_raw/*`` frame rows always; when ``dbc`` is supplied, also
    emits decoded ``can_codec/<message>`` signal rows.
    """

    def __init__(self, namespace: zelos_sdk.TraceNamespace, dbc: str | None = None) -> None:
        # ``source_name`` alone would bind the default namespace and leave the trace empty.
        kwargs: dict = {
            # The CAN extension's default source names, for one CAN bus per capture.
            "source": zelos_sdk.TraceSource("can_codec", namespace=namespace),
            "raw_source": zelos_sdk.TraceSource("can_raw", namespace=namespace),
            # With a DBC the decoder would otherwise stop logging raw frames.
            "log_raw_frames": True,
            "timestamp_mode": "absolute",
        }
        if dbc is not None:
            kwargs["database_file"] = str(dbc)
            kwargs["emit_schemas_on_init"] = True
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
