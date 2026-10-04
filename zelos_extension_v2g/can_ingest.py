"""Feed SocketCAN records into zelos-can's Rust ``CanDecoder``.

CAN frame cracking (raw logging + DBC signal decode, value tables, multiplexing)
lives in the shared ``zelos-can`` package; this is only the glue that nests a
capture's CAN rows under its V2G branch: ``<name>/CAN/Frame`` (raw,
``zelos.can.frame.v1``) and ``<name>/CAN/<message>`` (with a DBC), on the same
source object as that branch's V2G events.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import zelos_sdk
from zelos_can import CanDecoder

from .socketcan import parse_socketcan

logger = logging.getLogger(__name__)


class CanIngest:
    """A ``zelos-can`` ``CanDecoder`` writing into ``source`` under ``<name>/CAN``.

    ``dbcs`` are merged in order: a later file wins a message an earlier one defines
    differently.
    """

    def __init__(self, source: zelos_sdk.TraceSource, name: str, dbcs: Sequence[str] = ()) -> None:
        self.name = name
        # zelos.can.frame.v1 has no error flag: logging one as a data frame would lie.
        self.error_frames = 0
        self.bad_records = 0
        self._decoder = CanDecoder(
            database_file=[str(p) for p in dbcs] or None,
            # The branch's own source object: a second same-named source would
            # register separately and the query layer keeps only the newest.
            source=source,
            raw_source=source,
            event_prefix=f"{name}/CAN",
            raw_event_name=f"{name}/CAN/Frame",
            # Keep raw frames even when a DBC is decoding signals.
            log_raw_frames=True,
            timestamp_mode="absolute",
            emit_schemas_on_init=bool(dbcs),
        )

    def emit(self, ts_ns: int, record: bytes) -> None:
        f = parse_socketcan(record)
        if f is None:
            if not self.bad_records:
                logger.warning(
                    "%s: skipping malformed SocketCAN record (%d bytes); further ones counted",
                    self.name,
                    len(record),
                )
            self.bad_records += 1
            return
        if f.error:
            if not self.error_frames:
                logger.warning("%s: skipping CAN error frames (not representable)", self.name)
            self.error_frames += 1
            return
        self._decoder.decode_frame(
            arbitration_id=f.can_id,
            data=f.data,
            timestamp_ns=ts_ns,
            is_extended=f.extended,
            is_fd=f.fd,
            is_remote_frame=f.remote,
        )

    def metrics(self):
        return self._decoder.metrics()
