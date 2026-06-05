"""Turn a decoded V2G session into Zelos trace events.

Layer 1 — transport/handshake observability that needs no EXI codec: SLAC, SDP,
and the V2GTP message timeline (raw EXI retained per message).

Layer 2 — application-message field decode via the bundled libcbv2g shim
(``exi.libv2g``). Each DIN 70121 message type becomes its own event whose fields are
the standard signals (SoC, target/present voltage & current, response codes, …). If
no decode library is bundled for the platform, Layer 2 is skipped and Layer 1 stands.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import zelos_sdk

from . import slac
from .exi import libv2g
from .pcap import DecodedSession, SdpFrame, SlacFrame, V2gMessage

logger = logging.getLogger(__name__)

# ─── enum value tables (from the DIN 70121 schema, in schema order) ────────

RESPONSE_CODE = [
    "OK",
    "OK_NewSessionEstablished",
    "OK_OldSessionJoined",
    "OK_CertificateExpiresSoon",
    "FAILED",
    "FAILED_SequenceError",
    "FAILED_ServiceIDInvalid",
    "FAILED_UnknownSession",
    "FAILED_ServiceSelectionInvalid",
    "FAILED_PaymentSelectionInvalid",
    "FAILED_CertificateExpired",
    "FAILED_SignatureError",
    "FAILED_NoCertificateAvailable",
    "FAILED_CertChainError",
    "FAILED_ChallengeInvalid",
    "FAILED_ContractCanceled",
    "FAILED_WrongChargeParameter",
    "FAILED_PowerDeliveryNotApplied",
    "FAILED_TariffSelectionInvalid",
    "FAILED_ChargingProfileInvalid",
    "FAILED_EVSEPresentVoltageToLow",
    "FAILED_MeteringSignatureNotValid",
    "FAILED_WrongEnergyTransferType",
]
EVSE_STATUS_CODE = [
    "EVSE_NotReady",
    "EVSE_Ready",
    "EVSE_Shutdown",
    "EVSE_UtilityInterruptEvent",
    "EVSE_IsolationMonitoringActive",
    "EVSE_EmergencyShutdown",
    "EVSE_Malfunction",
    "Reserved_8",
    "Reserved_9",
    "Reserved_A",
    "Reserved_B",
    "Reserved_C",
]
EVSE_PROCESSING = ["Finished", "Ongoing", "Ongoing_WaitingForCustomerInteraction"]
ENERGY_TRANSFER = [
    "AC_single_phase_core",
    "AC_three_phase_core",
    "DC_core",
    "DC_extended",
    "DC_combo_core",
    "DC_unique",
]

_VALUE_TABLES = {
    "response_code": dict(enumerate(RESPONSE_CODE)),
    "evse_status_code": dict(enumerate(EVSE_STATUS_CODE)),
    "evse_processing": dict(enumerate(EVSE_PROCESSING)),
    "requested_energy_transfer": dict(enumerate(ENERGY_TRANSFER)),
}


# Field name -> (zelos DataType, unit). The shim↔codec contract: every field the
# libcbv2g shim emits must appear here, or it is dropped from the trace.
_DT = zelos_sdk.DataType
_FIELD_META: dict[str, tuple[Any, str | None]] = {
    "soc": (_DT.UInt8, "%"),
    "ev_target_voltage": (_DT.Float32, "V"),
    "ev_target_current": (_DT.Float32, "A"),
    "evse_present_voltage": (_DT.Float32, "V"),
    "evse_present_current": (_DT.Float32, "A"),
    "response_code": (_DT.UInt8, None),
    "evse_status_code": (_DT.UInt8, None),
    "evse_processing": (_DT.UInt8, None),
    "charging_complete": (_DT.Boolean, None),
    "evccid": (_DT.String, None),
    "protocol": (_DT.String, None),
    "version_major": (_DT.UInt8, None),
    "version_minor": (_DT.UInt8, None),
    "schema_id": (_DT.UInt8, None),
    "num_protocols": (_DT.UInt8, None),
    "evse_id": (_DT.String, None),
    "datetime_now": (_DT.Int64, "s"),
    "evse_max_voltage": (_DT.Float32, "V"),
    "evse_max_current": (_DT.Float32, "A"),
    "evse_max_power": (_DT.Float32, "W"),
    "requested_energy_transfer": (_DT.UInt8, None),
    "ev_max_voltage": (_DT.Float32, "V"),
    "ev_max_current": (_DT.Float32, "A"),
    "ev_max_power": (_DT.Float32, "W"),
    "ev_energy_capacity": (_DT.Float32, "Wh"),
    "full_soc": (_DT.UInt8, "%"),
    "bulk_soc": (_DT.UInt8, "%"),
}

# Coerce a decoded JSON value to the Python type the field's DataType expects.
_COERCERS = {_DT.Boolean: bool, _DT.String: str, _DT.Float32: float}

# supportedAppProtocol namespace -> friendly dialect label.
_PROTOCOL_NS = {
    "urn:din:70121:2012:MsgDef": "DIN 70121",
    "urn:iso:15118:2:2013:MsgDef": "ISO 15118-2",
}


def _protocol_label(namespace: str) -> str:
    return _PROTOCOL_NS.get(namespace, namespace)


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@dataclass
class ConversionStats:
    slac_frames: int = 0
    sdp_frames: int = 0
    messages: int = 0
    decoded_messages: int = 0
    protocol: str | None = None
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "slac_frames": self.slac_frames,
            "sdp_frames": self.sdp_frames,
            "messages": self.messages,
            "decoded_messages": self.decoded_messages,
            "protocol": self.protocol,
            "duration_seconds": round(self.duration_seconds, 3)
            if self.duration_seconds is not None
            else None,
        }


def _ts_ns(ts: float) -> int:
    return int(ts * 1e9)


class V2gCodec:
    """Registers V2G trace-event schemas and emits rows from a DecodedSession."""

    def __init__(
        self,
        namespace: zelos_sdk.TraceNamespace | None = None,
        source_name: str = "v2g",
    ) -> None:
        if namespace is not None:
            self.source = zelos_sdk.TraceSource(source_name, namespace=namespace)
        else:
            self.source = zelos_sdk.TraceSource(source_name)
        self._decoded_events: dict[str, Any] = {}
        self._define_layer1_schema()

    # ── Layer 1: framing ──────────────────────────────────────────────────

    def _define_layer1_schema(self) -> None:
        F = zelos_sdk.TraceEventFieldMetadata
        DT = zelos_sdk.DataType
        self.slac_event = self.source.add_event(
            "slac",
            [
                F("mmtype", DT.UInt16),
                F("name", DT.String),
                F("src_mac", DT.String),
                F("dst_mac", DT.String),
                F("data", DT.Binary),  # raw MME bytes, as seen on the wire
            ],
        )
        self.sdp_event = self.source.add_event(
            "sdp",
            [
                F("kind", DT.String),
                F("secc_ip", DT.String),
                F("secc_port", DT.UInt16),
                F("security", DT.String),
                F("transport", DT.String),
            ],
        )
        self.message_event = self.source.add_event(
            "message",
            [
                F("index", DT.UInt32),
                F("direction", DT.String),
                F("payload_type", DT.UInt16),
                F("length", DT.UInt32, "bytes"),
                F("name", DT.String),
                F("exi", DT.Binary),
            ],
        )
        # Decoded fields carried by individual SLAC frames (strictly per-frame).
        self.slac_attenuation_event = self.source.add_event(
            "slac_attenuation",  # one row per CM_ATTEN_CHAR.IND
            [
                F("run_id", DT.String),
                F("num_sounds", DT.UInt8),
                F("num_groups", DT.UInt8),
                F("atten_min", DT.UInt8, "dB"),
                F("atten_max", DT.UInt8, "dB"),
                F("atten_mean", DT.Float32, "dB"),
            ],
        )
        self.slac_match_event = self.source.add_event(
            "slac_match",  # one row per CM_SLAC_MATCH.CNF
            [
                F("run_id", DT.String),
                F("nid", DT.String),
                F("nmk", DT.String),
            ],
        )

    # ── Layer 2: decoded application messages (lazy per-type schema) ───────

    def _decoded_event(self, msg: str, fields: list[str]) -> Any:
        # Schema is created once from the first instance's field set; safe because
        # the shim emits a fixed field set per message type.
        event = self._decoded_events.get(msg)
        if event is not None:
            return event
        F = zelos_sdk.TraceEventFieldMetadata
        metas = [F(f, *_FIELD_META[f]) for f in fields if f in _FIELD_META]
        if not metas:
            return None
        event = self.source.add_event(_snake(msg), metas)
        for f in fields:
            if f in _VALUE_TABLES:
                self.source.add_value_table(_snake(msg), f, _VALUE_TABLES[f])
        self._decoded_events[msg] = event
        return event

    def _emit_decoded(self, decoded: dict, ts_ns: int) -> bool:
        msg = decoded.get("msg")
        if not msg:
            return False
        fields = [k for k in decoded if k != "msg"]
        event = self._decoded_event(msg, fields)
        if event is None:
            return False
        signals: dict[str, Any] = {}
        for f in fields:
            meta = _FIELD_META.get(f)
            if meta is None:
                logger.debug("decoded field %r of %s has no Zelos mapping; skipped", f, msg)
                continue
            signals[f] = _COERCERS.get(meta[0], int)(decoded[f])
        event.log_at(ts_ns, **signals)
        return True

    # ── per-record emit (shared by batch convert + live capture) ──────────

    def emit_slac(self, f: SlacFrame) -> None:
        self.slac_event.log_at(
            _ts_ns(f.ts),
            mmtype=f.mmtype,
            name=f.name,
            src_mac=f.src_mac,
            dst_mac=f.dst_mac,
            data=f.payload,
        )
        # Decode the fields this specific frame carries (per-frame, no aggregation).
        if f.name == "CM_ATTEN_CHAR.IND":
            a = slac.parse_atten_char_ind(f.payload)
            if a:
                aag = a["aag"]
                self.slac_attenuation_event.log_at(
                    _ts_ns(f.ts),
                    run_id=a["run_id"],
                    num_sounds=a["num_sounds"],
                    num_groups=a["num_groups"],
                    atten_min=min(aag),
                    atten_max=max(aag),
                    atten_mean=sum(aag) / len(aag),
                )
        elif f.name == "CM_SLAC_MATCH.CNF":
            m = slac.parse_slac_match_cnf(f.payload)
            if m:
                self.slac_match_event.log_at(
                    _ts_ns(f.ts), run_id=m["run_id"], nid=m["nid"], nmk=m["nmk"]
                )

    def emit_sdp(self, f: SdpFrame) -> None:
        self.sdp_event.log_at(
            _ts_ns(f.ts),
            kind=f.kind,
            secc_ip=f.secc_ip or "",
            secc_port=f.secc_port or 0,
            security=f.security,
            transport=f.transport,
        )

    def emit_message(self, m: V2gMessage) -> tuple[dict | None, str | None, bool]:
        """Emit the raw message row + (if decodable) its field event.

        Returns (decoded_dict_or_None, dialect_or_None, emitted_field_event), where
        ``dialect`` is the grammar that actually decoded this message (factual, never
        guessed): the SAP-negotiated protocol, or the DIN/ISO grammar that matched.
        """
        ts_ns = _ts_ns(m.ts)
        decoded: dict | None = None
        dialect: str | None = None
        if libv2g.available():
            if (d := libv2g.decode_din(m.exi)) is not None:
                decoded, dialect = d, "DIN 70121"
            elif (d := libv2g.decode_iso2(m.exi)) is not None:
                decoded, dialect = d, "ISO 15118-2"
            elif (d := libv2g.decode_sap(m.exi)) is not None:
                decoded, dialect = d, _protocol_label(d.get("protocol", ""))
        self.message_event.log_at(
            ts_ns,
            index=m.index,
            direction=m.direction,
            payload_type=m.payload_type,
            length=m.length,
            name=decoded["msg"] if decoded else "(exi)",
            exi=m.exi,
        )
        emitted = bool(decoded and self._emit_decoded(decoded, ts_ns))
        return decoded, dialect, emitted

    # ── batch driver ──────────────────────────────────────────────────────

    def process(self, session: DecodedSession) -> ConversionStats:
        stats = ConversionStats()
        if session.start_ts is not None and session.end_ts is not None:
            stats.duration_seconds = session.end_ts - session.start_ts

        for f in session.slac:
            self.emit_slac(f)
            stats.slac_frames += 1

        for f in session.sdp:
            self.emit_sdp(f)
            stats.sdp_frames += 1

        if not libv2g.available():
            logger.warning("No libcbv2g shim for this platform; emitting Layer-1 framing only")
        for m in session.messages:
            stats.messages += 1
            _decoded, dialect, emitted = self.emit_message(m)
            if emitted:
                stats.decoded_messages += 1
            if dialect and stats.protocol is None:
                stats.protocol = dialect

        logger.info("Emitted V2G trace: %s", stats.to_dict())
        return stats
