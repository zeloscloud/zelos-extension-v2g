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
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import zelos_sdk
from scapy.config import conf

# Importing registers DLT 227 (SocketCAN): its records dissect as CAN (CANFD when 72
# bytes), so the link type, not a guess from the bytes, says what is CAN.
from scapy.layers.can import CAN

from . import slac
from .can_ingest import CanIngest
from .exi import libv2g
from .pcap import SdpFrame, SlacFrame, V2gMessage
from .stream import V2gStreamDecoder

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

# supportedAppProtocol has its own response codes.
_SAP_RESPONSE_CODE = dict(
    enumerate(
        [
            "OK_SuccessfulNegotiation",
            "OK_SuccessfulNegotiationWithMinorDeviation",
            "Failed_NoNegotiation",
        ]
    )
)

_VALUE_TABLES = {
    "response_code": dict(enumerate(RESPONSE_CODE)),
    "evse_status_code": dict(enumerate(EVSE_STATUS_CODE)),
    "evse_processing": dict(enumerate(EVSE_PROCESSING)),
    "requested_energy_transfer": dict(enumerate(ENERGY_TRANSFER)),
}


# Message -> every field the shim can emit for it (DIN and ISO 15118-2 share names),
# so each event's schema is complete up front: the shim emits optional fields only
# when present. The shim↔codec contract: a field missing here is dropped.
_MSG_FIELDS: dict[str, tuple[str, ...]] = {
    "SessionSetupReq": ("evccid",),
    "SessionSetupRes": ("response_code", "evse_id", "datetime_now"),
    "ServiceDiscoveryRes": ("response_code",),
    "ServicePaymentSelectionRes": ("response_code",),
    "PaymentServiceSelectionRes": ("response_code",),
    "ContractAuthenticationRes": ("response_code",),
    "AuthorizationRes": ("response_code",),
    "ChargeParameterDiscoveryReq": (
        "requested_energy_transfer",
        "soc",
        "ev_max_voltage",
        "ev_max_current",
        "ev_max_power",
        "ev_energy_capacity",
        "full_soc",
        "bulk_soc",
    ),
    "ChargeParameterDiscoveryRes": (
        "response_code",
        "evse_processing",
        "evse_max_voltage",
        "evse_max_current",
        "evse_max_power",
    ),
    "CableCheckReq": ("soc",),
    "CableCheckRes": ("response_code", "evse_processing", "evse_status_code"),
    "PreChargeReq": ("soc", "ev_target_voltage", "ev_target_current"),
    "PreChargeRes": ("response_code", "evse_present_voltage", "evse_status_code"),
    "PowerDeliveryRes": ("response_code",),
    "CurrentDemandReq": ("soc", "ev_target_voltage", "ev_target_current", "charging_complete"),
    "CurrentDemandRes": (
        "response_code",
        "evse_present_voltage",
        "evse_present_current",
        "evse_status_code",
    ),
    "ChargingStatusRes": ("response_code",),
    "WeldingDetectionRes": ("response_code", "evse_present_voltage"),
    "SessionStopRes": ("response_code",),
    "SupportedAppProtocolReq": (
        "num_protocols",
        "protocol",
        "version_major",
        "version_minor",
        "schema_id",
    ),
    "SupportedAppProtocolRes": ("response_code", "schema_id"),
}

# Field name -> (zelos DataType, unit), widths per the DIN / ISO 15118-2 / SAP XSD
# types (percentValueType is xs:byte; versions are xs:unsignedInt).
_DT = zelos_sdk.DataType
_FIELD_META: dict[str, tuple[Any, str | None]] = {
    "soc": (_DT.Int8, "%"),
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
    "version_major": (_DT.UInt32, None),
    "version_minor": (_DT.UInt32, None),
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
    "full_soc": (_DT.Int8, "%"),
    "bulk_soc": (_DT.Int8, "%"),
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "slac_frames": self.slac_frames,
            "sdp_frames": self.sdp_frames,
            "messages": self.messages,
            "decoded_messages": self.decoded_messages,
            "protocol": self.protocol,
        }


def _ts_ns(t) -> int:
    """``pkt.time`` -> epoch ns. Exact for scapy's Decimal capture stamps (no float)."""
    return int(t * 10**9)


def trace_layout(prefix: str, name: str) -> tuple[str, str | None]:
    """The one trace-naming rule: ``(source name, event prefix or None)``.

    With a prefix, one source carries every branch and each branch's events nest
    under ``<name>/``. Cleared, the branch owns a source named ``<name>`` and its
    events are unprefixed.
    """
    return (prefix, name) if prefix else (name, None)


class V2gCodec:
    """One capture branch: decodes frames and emits its V2G events (and, when
    ``packets`` is set, a raw ``zelos.packet.v1`` row per frame) into ``source``.
    """

    def __init__(
        self,
        source: zelos_sdk.TraceSource,
        name: str,
        event_prefix: str | None = None,
        packets: Any = None,
        can: bool = False,
        dbcs: Sequence[str] = (),
    ) -> None:
        self.source = source
        self.name = name
        # Set for file paths (convert, replay, stdin): SocketCAN frames decode into
        # `<name>/CAN/...`, the CanIngest created on the first one.
        self.decode_can = can
        self.dbcs = list(dbcs)
        self.can: CanIngest | None = None
        self._prefix = f"{event_prefix}/" if event_prefix else ""
        self.packets = packets  # zelos_packet.PacketDecoder or None
        self.stats = ConversionStats()
        self.frames = 0
        self.frame_errors: Counter[str] = Counter()
        self._decoded_events: dict[str, Any] = {}
        self._define_layer1_schema()
        self._stream = V2gStreamDecoder(
            on_slac=self.emit_slac, on_sdp=self.emit_sdp, on_message=self.emit_message
        )

    def _event(self, name: str) -> str:
        return self._prefix + name

    # ── frame in (live, replay, stdin, convert) ───────────────────────────

    def feed(self, pkt) -> None:
        """One captured frame, all rows stamped ``pkt.time``. Never raises: a frame
        that fails is logged (first per exception type) and counted, so one bad
        frame cannot end a capture."""
        self.frames += 1
        try:
            self._feed(pkt)
        except Exception as exc:  # noqa: BLE001 - see docstring
            kind = type(exc).__name__
            if kind not in self.frame_errors:
                logger.exception(
                    "%s: frame %d (t=%s) failed; further %s are counted",
                    self.name,
                    self.frames,
                    pkt.time,
                    kind,
                )
            self.frame_errors[kind] += 1

    def _feed(self, pkt) -> None:
        ts_ns = _ts_ns(pkt.time)
        raw = pkt.original or bytes(pkt)
        if self.decode_can and isinstance(pkt, CAN):
            if self.can is None:
                self.can = CanIngest(self.source, self.name, self.dbcs)
            self.can.emit(ts_ns, raw)
            return
        dlt = conf.l2types.layer2num.get(type(pkt))
        if self.packets is not None and dlt is not None:
            self.packets.decode_frame(
                raw, link_type=dlt, timestamp_ns=ts_ns, orig_len=getattr(pkt, "wirelen", None)
            )
        self._stream.feed_packet(pkt, ts_ns)

    def flush(self) -> None:
        """Push buffered packet rows through; ``decode_frame`` has no timer of its own."""
        if self.packets is not None:
            self.packets.flush()

    def report_errors(self) -> None:
        """Log the per-type count of frames that failed, if any."""
        if self.frame_errors:
            logger.error(
                "%s: %d of %d frames failed: %s",
                self.name,
                self.frame_errors.total(),
                self.frames,
                dict(self.frame_errors),
            )

    # ── Layer 1: framing ──────────────────────────────────────────────────

    def _define_layer1_schema(self) -> None:
        F = zelos_sdk.TraceEventFieldMetadata
        DT = zelos_sdk.DataType
        self.slac_event = self.source.add_event(
            self._event("slac"),
            [
                F("mmtype", DT.UInt16),
                F("name", DT.String),
                F("src_mac", DT.String),
                F("dst_mac", DT.String),
                F("data", DT.Binary),  # raw MME bytes, as seen on the wire
            ],
        )
        self.sdp_event = self.source.add_event(
            self._event("sdp"),
            [
                F("kind", DT.String),
                F("secc_ip", DT.String),
                F("secc_port", DT.UInt16),
                F("security", DT.String),
                F("transport", DT.String),
            ],
        )
        self.message_event = self.source.add_event(
            self._event("message"),
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
            self._event("slac_attenuation"),  # one row per CM_ATTEN_CHAR.IND
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
            self._event("slac_match"),  # one row per CM_SLAC_MATCH.CNF
            [
                F("run_id", DT.String),
                F("nid", DT.String),
                F("nmk", DT.String),
            ],
        )

    # ── Layer 2: decoded application messages (per-type schema from _MSG_FIELDS) ──

    def _decoded_event(self, msg: str) -> Any:
        if msg in self._decoded_events:
            return self._decoded_events[msg]
        fields = _MSG_FIELDS.get(msg, ())
        event = None
        if fields:
            F = zelos_sdk.TraceEventFieldMetadata
            name = self._event(_snake(msg))
            event = self.source.add_event(name, [F(f, *_FIELD_META[f]) for f in fields])
            for f in fields:
                table = _VALUE_TABLES.get(f)
                if msg == "SupportedAppProtocolRes" and f == "response_code":
                    table = _SAP_RESPONSE_CODE
                if table:
                    self.source.add_value_table(name, f, table)
        self._decoded_events[msg] = event
        return event

    def _emit_decoded(self, decoded: dict, ts_ns: int) -> bool:
        msg = decoded.get("msg")
        event = self._decoded_event(msg) if msg else None
        if event is None:
            return False
        fields = _MSG_FIELDS[msg]
        signals: dict[str, Any] = {}
        for f, v in decoded.items():
            if f in fields:
                signals[f] = _COERCERS.get(_FIELD_META[f][0], int)(v)
            elif f != "msg":
                logger.debug("decoded field %r of %s has no Zelos mapping; skipped", f, msg)
        event.log_at(ts_ns, **signals)
        return True

    # ── per-record emit ───────────────────────────────────────────────────

    def emit_slac(self, f: SlacFrame) -> None:
        self.stats.slac_frames += 1
        self.slac_event.log_at(
            f.ts_ns,
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
                    f.ts_ns,
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
                    f.ts_ns, run_id=m["run_id"], nid=m["nid"], nmk=m["nmk"]
                )

    def emit_sdp(self, f: SdpFrame) -> None:
        self.stats.sdp_frames += 1
        self.sdp_event.log_at(
            f.ts_ns,
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
        ts_ns = m.ts_ns
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
        self.stats.messages += 1
        self.stats.decoded_messages += emitted
        if dialect and self.stats.protocol is None:
            self.stats.protocol = dialect
        return decoded, dialect, emitted
