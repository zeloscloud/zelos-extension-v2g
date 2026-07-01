"""Feed SocketCAN frames into zelos-can's Rust ``CanDecoder``.

The CAN frame cracking (raw logging + DBC signal decode, value tables,
multiplexing, cantools-parity) lives in the shared ``zelos-can`` package — we do
**not** reimplement it here. This module is only the thin glue that binds a
``CanDecoder`` to a caller-provided :class:`~zelos_sdk.TraceNamespace` and hands
it parsed frames, so CAN rows land in the same ``.trz`` as the V2G rows.

Requires ``zelos-can >= 0.0.7a0``: the DBC is optional there (a decoder built
with no database logs raw frames only), which is how a DBC-less capture is
handled — no empty-DBC placeholder needed.
"""

from __future__ import annotations

import zelos_sdk
from zelos_can import CanDecoder

from .socketcan import CanFrame


class CanIngest:
    """A ``zelos-can`` ``CanDecoder`` bound to ``namespace``.

    Emits raw ``can_raw/*`` frame rows always; when ``dbc`` is supplied, also
    emits decoded ``can/<message>`` signal rows.
    """

    def __init__(self, namespace: zelos_sdk.TraceNamespace, dbc: str | None = None) -> None:
        # Bind the decoder's trace sources to THIS namespace. Passing only
        # ``source_name`` would bind the process-default namespace, and a
        # namespaced ``TraceWriter`` would then capture nothing (empty trace).
        kwargs: dict = {
            "source": zelos_sdk.TraceSource("can", namespace=namespace),
            "raw_source": zelos_sdk.TraceSource("can_raw", namespace=namespace),
            # Keep raw frames even when a DBC is decoding signals (with a DBC the
            # decoder would otherwise default this off).
            "log_raw_frames": True,
            "timestamp_mode": "absolute",
        }
        if dbc is not None:
            kwargs["database_file"] = str(dbc)
            kwargs["emit_schemas_on_init"] = True
        # No DBC -> raw-frame-only decoder (zelos-can >= 0.0.7a0 optional DBC).
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
