/* Thin shim over libcbv2g: decode a DIN 70121 V2G EXI message to a compact JSON
 * object of the telemetry-relevant fields. Returns bytes written (>0) or <0 on error.
 * Pure C; built into a self-contained shared library and called via Python ctypes.
 * Every field emitted per message must be listed in codec._MSG_FIELDS; an optional
 * element is emitted only when its _isUsed flag is set (else the value is garbage). */
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include "cbv2g/din/din_msgDefDecoder.h"
#include "cbv2g/app_handshake/appHand_Decoder.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/common/exi_bitstream.h"

struct buf { char *p; int cap; int n; };
static void emit(struct buf *b, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (b->n < b->cap) b->n += vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
}
static double pv(const struct din_PhysicalValueType *p) { return p->Value * pow(10.0, p->Multiplier); }
static double pv2(const struct iso2_PhysicalValueType *p) { return p->Value * pow(10.0, p->Multiplier); }

/* Quoted JSON strings: hex for byte fields, escaped for (ASCII) character fields. */
static void emit_hex(struct buf *o, const uint8_t *p, int n) {
    emit(o, "\"");
    for (int i = 0; i < n; i++) emit(o, "%02x", p[i]);
    emit(o, "\"");
}
static void emit_str(struct buf *o, const char *p, int n) {
    emit(o, "\"");
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '"' || c == '\\') emit(o, "\\%c", c);
        else if (c < 0x20 || c > 0x7e) emit(o, "\\u%04x", c);
        else emit(o, "%c", c);
    }
    emit(o, "\"");
}

/* Enum list -> one comma-separated string of XSD names (an unknown value as its number). */
static const char *const DIN_ENERGY_TRANSFER[] = {
    "AC_single_phase_core", "AC_three_phase_core", "DC_core", "DC_extended", "DC_combo_core",
    "DC_dual", "AC_core1p_DC_extended", "AC_single_DC_core",
    "AC_single_phase_three_phase_core_DC_extended", "AC_core3p_DC_extended"};
static const char *const ISO2_ENERGY_TRANSFER[] = {
    "AC_single_phase_core", "AC_three_phase_core", "DC_core", "DC_extended", "DC_combo_core",
    "DC_unique"};
static const char *const PAYMENT_OPTION[] = {"Contract", "ExternalPayment"};
#define NAMES(t) t, (unsigned)(sizeof(t) / sizeof(t[0]))
static void emit_name(struct buf *o, int i, unsigned v, const char *const *t, unsigned nt) {
    if (i) emit(o, ",");
    if (v < nt) emit(o, "%s", t[v]); else emit(o, "%u", v);
}

static void begin(struct buf *o, const char *name, const uint8_t *sid, int n) {
    emit(o, "{\"msg\":\"%s\",\"session_id\":", name);
    emit_hex(o, sid, n);
}
#define M(name) begin(&o, name, hdr->SessionID.bytes, hdr->SessionID.bytesLen)

/* DC_EVStatus (requests) and DC_EVSEStatus (responses); DIN adds the conditioning flags. */
static void ev_status_din(struct buf *o, const struct din_DC_EVStatusType *s) {
    emit(o, ",\"soc\":%d,\"ev_ready\":%d,\"ev_error_code\":%d", s->EVRESSSOC, s->EVReady, s->EVErrorCode);
    if (s->EVCabinConditioning_isUsed) emit(o, ",\"ev_cabin_conditioning\":%d", s->EVCabinConditioning);
    if (s->EVRESSConditioning_isUsed) emit(o, ",\"ev_ress_conditioning\":%d", s->EVRESSConditioning);
}
static void ev_status_iso2(struct buf *o, const struct iso2_DC_EVStatusType *s) {
    emit(o, ",\"soc\":%d,\"ev_ready\":%d,\"ev_error_code\":%d", s->EVRESSSOC, s->EVReady, s->EVErrorCode);
}
static void evse_status_din(struct buf *o, const struct din_DC_EVSEStatusType *s) {
    emit(o, ",\"evse_status_code\":%d,\"evse_notification\":%d,\"notification_max_delay\":%u",
         s->EVSEStatusCode, s->EVSENotification, s->NotificationMaxDelay);
    if (s->EVSEIsolationStatus_isUsed) emit(o, ",\"evse_isolation_status\":%d", s->EVSEIsolationStatus);
}
static void evse_status_iso2(struct buf *o, const struct iso2_DC_EVSEStatusType *s) {
    emit(o, ",\"evse_status_code\":%d,\"evse_notification\":%d,\"notification_max_delay\":%u",
         s->EVSEStatusCode, s->EVSENotification, s->NotificationMaxDelay);
    if (s->EVSEIsolationStatus_isUsed) emit(o, ",\"evse_isolation_status\":%d", s->EVSEIsolationStatus);
}

int v2g_din_decode_json(const uint8_t *data, int len, char *out, int cap) {
    exi_bitstream_t s;
    exi_bitstream_init(&s, (uint8_t *)data, (size_t)len, 0, NULL);
    struct din_exiDocument doc;
    int rc = decode_din_exiDocument(&s, &doc);
    if (rc != 0) return rc < 0 ? rc : -rc;
    struct din_MessageHeaderType *hdr = &doc.V2G_Message.Header;
    struct din_BodyType *b = &doc.V2G_Message.Body;
    struct buf o = {out, cap, 0};

    if (b->SessionSetupReq_isUsed) {
        M("SessionSetupReq"); emit(&o, ",\"evccid\":");
        emit_hex(&o, b->SessionSetupReq.EVCCID.bytes, b->SessionSetupReq.EVCCID.bytesLen);
    } else if (b->SessionSetupRes_isUsed) {
        struct din_SessionSetupResType *m = &b->SessionSetupRes;
        M("SessionSetupRes");
        emit(&o, ",\"response_code\":%d,\"evse_id\":", m->ResponseCode);
        emit_hex(&o, m->EVSEID.bytes, m->EVSEID.bytesLen);
        if (m->DateTimeNow_isUsed) emit(&o, ",\"datetime_now\":%lld", (long long)m->DateTimeNow);
    }
    else if (b->ServiceDiscoveryReq_isUsed) M("ServiceDiscoveryReq");
    else if (b->ServiceDiscoveryRes_isUsed) {
        struct din_ServiceDiscoveryResType *m = &b->ServiceDiscoveryRes;
        M("ServiceDiscoveryRes");
        emit(&o, ",\"response_code\":%d,\"payment_options\":\"", m->ResponseCode);
        for (int i = 0; i < m->PaymentOptions.PaymentOption.arrayLen; i++)
            emit_name(&o, i, m->PaymentOptions.PaymentOption.array[i], NAMES(PAYMENT_OPTION));
        emit(&o, "\",\"energy_transfer_modes\":\"");
        emit_name(&o, 0, m->ChargeService.EnergyTransferType, NAMES(DIN_ENERGY_TRANSFER));
        emit(&o, "\"");
    }
    else if (b->ServicePaymentSelectionReq_isUsed) { M("ServicePaymentSelectionReq"); emit(&o, ",\"selected_payment_option\":%d", b->ServicePaymentSelectionReq.SelectedPaymentOption); }
    else if (b->ServicePaymentSelectionRes_isUsed) { M("ServicePaymentSelectionRes"); emit(&o, ",\"response_code\":%d", b->ServicePaymentSelectionRes.ResponseCode); }
    else if (b->ContractAuthenticationReq_isUsed) M("ContractAuthenticationReq");
    else if (b->ContractAuthenticationRes_isUsed) { M("ContractAuthenticationRes"); emit(&o, ",\"response_code\":%d", b->ContractAuthenticationRes.ResponseCode); }
    else if (b->ChargeParameterDiscoveryReq_isUsed) {
        struct din_ChargeParameterDiscoveryReqType *m = &b->ChargeParameterDiscoveryReq;
        M("ChargeParameterDiscoveryReq");
        emit(&o, ",\"requested_energy_transfer\":%d", m->EVRequestedEnergyTransferType);
        if (m->DC_EVChargeParameter_isUsed) {
            struct din_DC_EVChargeParameterType *d = &m->DC_EVChargeParameter;
            ev_status_din(&o, &d->DC_EVStatus);
            emit(&o, ",\"ev_max_voltage\":%g,\"ev_max_current\":%g",
                 pv(&d->EVMaximumVoltageLimit), pv(&d->EVMaximumCurrentLimit));
            if (d->EVMaximumPowerLimit_isUsed)
                emit(&o, ",\"ev_max_power\":%g", pv(&d->EVMaximumPowerLimit));
            if (d->EVEnergyCapacity_isUsed)
                emit(&o, ",\"ev_energy_capacity\":%g", pv(&d->EVEnergyCapacity));
            if (d->FullSOC_isUsed) emit(&o, ",\"full_soc\":%d", d->FullSOC);
            if (d->BulkSOC_isUsed) emit(&o, ",\"bulk_soc\":%d", d->BulkSOC);
        }
    }
    else if (b->ChargeParameterDiscoveryRes_isUsed) {
        struct din_ChargeParameterDiscoveryResType *m = &b->ChargeParameterDiscoveryRes;
        M("ChargeParameterDiscoveryRes");
        emit(&o, ",\"response_code\":%d,\"evse_processing\":%d", m->ResponseCode, m->EVSEProcessing);
        if (m->DC_EVSEChargeParameter_isUsed) {
            struct din_DC_EVSEChargeParameterType *d = &m->DC_EVSEChargeParameter;
            evse_status_din(&o, &d->DC_EVSEStatus);
            emit(&o, ",\"evse_max_voltage\":%g,\"evse_max_current\":%g,\"evse_min_voltage\":%g,"
                     "\"evse_min_current\":%g,\"evse_peak_current_ripple\":%g",
                 pv(&d->EVSEMaximumVoltageLimit), pv(&d->EVSEMaximumCurrentLimit),
                 pv(&d->EVSEMinimumVoltageLimit), pv(&d->EVSEMinimumCurrentLimit),
                 pv(&d->EVSEPeakCurrentRipple));
            if (d->EVSEMaximumPowerLimit_isUsed)
                emit(&o, ",\"evse_max_power\":%g", pv(&d->EVSEMaximumPowerLimit));
            if (d->EVSECurrentRegulationTolerance_isUsed)
                emit(&o, ",\"evse_current_regulation_tolerance\":%g", pv(&d->EVSECurrentRegulationTolerance));
            if (d->EVSEEnergyToBeDelivered_isUsed)
                emit(&o, ",\"evse_energy_to_be_delivered\":%g", pv(&d->EVSEEnergyToBeDelivered));
        }
    }
    else if (b->CableCheckReq_isUsed) { M("CableCheckReq"); ev_status_din(&o, &b->CableCheckReq.DC_EVStatus); }
    else if (b->CableCheckRes_isUsed) { M("CableCheckRes"); emit(&o, ",\"response_code\":%d,\"evse_processing\":%d", b->CableCheckRes.ResponseCode, b->CableCheckRes.EVSEProcessing); evse_status_din(&o, &b->CableCheckRes.DC_EVSEStatus); }
    else if (b->PreChargeReq_isUsed) { M("PreChargeReq"); ev_status_din(&o, &b->PreChargeReq.DC_EVStatus); emit(&o, ",\"ev_target_voltage\":%g,\"ev_target_current\":%g", pv(&b->PreChargeReq.EVTargetVoltage), pv(&b->PreChargeReq.EVTargetCurrent)); }
    else if (b->PreChargeRes_isUsed) { M("PreChargeRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->PreChargeRes.ResponseCode, pv(&b->PreChargeRes.EVSEPresentVoltage)); evse_status_din(&o, &b->PreChargeRes.DC_EVSEStatus); }
    else if (b->PowerDeliveryReq_isUsed) {
        struct din_PowerDeliveryReqType *m = &b->PowerDeliveryReq;
        M("PowerDeliveryReq");
        emit(&o, ",\"ready_to_charge\":%d", m->ReadyToChargeState);
        if (m->DC_EVPowerDeliveryParameter_isUsed) ev_status_din(&o, &m->DC_EVPowerDeliveryParameter.DC_EVStatus);
    }
    else if (b->PowerDeliveryRes_isUsed) {
        M("PowerDeliveryRes"); emit(&o, ",\"response_code\":%d", b->PowerDeliveryRes.ResponseCode);
        if (b->PowerDeliveryRes.DC_EVSEStatus_isUsed) evse_status_din(&o, &b->PowerDeliveryRes.DC_EVSEStatus);
    }
    else if (b->CurrentDemandReq_isUsed) {
        struct din_CurrentDemandReqType *m = &b->CurrentDemandReq;
        M("CurrentDemandReq");
        ev_status_din(&o, &m->DC_EVStatus);
        emit(&o, ",\"ev_target_voltage\":%g,\"ev_target_current\":%g,\"charging_complete\":%d",
             pv(&m->EVTargetVoltage), pv(&m->EVTargetCurrent), m->ChargingComplete);
        if (m->EVMaximumVoltageLimit_isUsed) emit(&o, ",\"ev_max_voltage\":%g", pv(&m->EVMaximumVoltageLimit));
        if (m->EVMaximumCurrentLimit_isUsed) emit(&o, ",\"ev_max_current\":%g", pv(&m->EVMaximumCurrentLimit));
        if (m->EVMaximumPowerLimit_isUsed) emit(&o, ",\"ev_max_power\":%g", pv(&m->EVMaximumPowerLimit));
        if (m->BulkChargingComplete_isUsed) emit(&o, ",\"bulk_charging_complete\":%d", m->BulkChargingComplete);
        if (m->RemainingTimeToFullSoC_isUsed) emit(&o, ",\"remaining_time_to_full_soc\":%g", pv(&m->RemainingTimeToFullSoC));
        if (m->RemainingTimeToBulkSoC_isUsed) emit(&o, ",\"remaining_time_to_bulk_soc\":%g", pv(&m->RemainingTimeToBulkSoC));
    }
    else if (b->CurrentDemandRes_isUsed) {
        struct din_CurrentDemandResType *m = &b->CurrentDemandRes;
        M("CurrentDemandRes");
        emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_present_current\":%g,"
                 "\"evse_current_limit_achieved\":%d,\"evse_voltage_limit_achieved\":%d,"
                 "\"evse_power_limit_achieved\":%d",
             m->ResponseCode, pv(&m->EVSEPresentVoltage), pv(&m->EVSEPresentCurrent),
             m->EVSECurrentLimitAchieved, m->EVSEVoltageLimitAchieved, m->EVSEPowerLimitAchieved);
        evse_status_din(&o, &m->DC_EVSEStatus);
        if (m->EVSEMaximumVoltageLimit_isUsed) emit(&o, ",\"evse_max_voltage\":%g", pv(&m->EVSEMaximumVoltageLimit));
        if (m->EVSEMaximumCurrentLimit_isUsed) emit(&o, ",\"evse_max_current\":%g", pv(&m->EVSEMaximumCurrentLimit));
        if (m->EVSEMaximumPowerLimit_isUsed) emit(&o, ",\"evse_max_power\":%g", pv(&m->EVSEMaximumPowerLimit));
    }
    else if (b->WeldingDetectionReq_isUsed) { M("WeldingDetectionReq"); ev_status_din(&o, &b->WeldingDetectionReq.DC_EVStatus); }
    else if (b->WeldingDetectionRes_isUsed) { M("WeldingDetectionRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->WeldingDetectionRes.ResponseCode, pv(&b->WeldingDetectionRes.EVSEPresentVoltage)); evse_status_din(&o, &b->WeldingDetectionRes.DC_EVSEStatus); }
    else if (b->SessionStopReq_isUsed) M("SessionStopReq");
    else if (b->SessionStopRes_isUsed) { M("SessionStopRes"); emit(&o, ",\"response_code\":%d", b->SessionStopRes.ResponseCode); }
    else M("Unknown");
    emit(&o, "}");
    return o.n;
}

/* Decode the supportedAppProtocol (SAP) handshake — a separate schema from the V2G
 * messages. Surfaces the negotiated protocol namespace + version. */
int v2g_apphand_decode_json(const uint8_t *data, int len, char *out, int cap) {
    exi_bitstream_t s;
    exi_bitstream_init(&s, (uint8_t *)data, (size_t)len, 0, NULL);
    struct appHand_exiDocument doc;
    int rc = decode_appHand_exiDocument(&s, &doc);
    if (rc != 0) return rc < 0 ? rc : -rc;
    struct buf o = {out, cap, 0};
    if (doc.supportedAppProtocolReq_isUsed) {
        struct appHand_supportedAppProtocolReq *m = &doc.supportedAppProtocolReq;
        emit(&o, "{\"msg\":\"SupportedAppProtocolReq\",\"num_protocols\":%u", m->AppProtocol.arrayLen);
        if (m->AppProtocol.arrayLen > 0) {
            struct appHand_AppProtocolType *ap = &m->AppProtocol.array[0];
            emit(&o, ",\"protocol\":");
            emit_str(&o, ap->ProtocolNamespace.characters, ap->ProtocolNamespace.charactersLen);
            emit(&o, ",\"version_major\":%u,\"version_minor\":%u,\"schema_id\":%u",
                 ap->VersionNumberMajor, ap->VersionNumberMinor, ap->SchemaID);
        }
        emit(&o, "}");
    } else if (doc.supportedAppProtocolRes_isUsed) {
        emit(&o, "{\"msg\":\"SupportedAppProtocolRes\",\"response_code\":%d", doc.supportedAppProtocolRes.ResponseCode);
        if (doc.supportedAppProtocolRes.SchemaID_isUsed)
            emit(&o, ",\"schema_id\":%u", doc.supportedAppProtocolRes.SchemaID);
        emit(&o, "}");
    } else {
        emit(&o, "{\"msg\":\"SupportedAppProtocol\"}");
    }
    return o.n;
}

/* Decode an ISO 15118-2 V2G EXI message. Mirrors the DIN decoder; emits the same
 * field names so the Python codec reuses its event schemas. */
int v2g_iso2_decode_json(const uint8_t *data, int len, char *out, int cap) {
    exi_bitstream_t s;
    exi_bitstream_init(&s, (uint8_t *)data, (size_t)len, 0, NULL);
    struct iso2_exiDocument doc;
    int rc = decode_iso2_exiDocument(&s, &doc);
    if (rc != 0) return rc < 0 ? rc : -rc;
    struct iso2_MessageHeaderType *hdr = &doc.V2G_Message.Header;
    struct iso2_BodyType *b = &doc.V2G_Message.Body;
    struct buf o = {out, cap, 0};

    if (b->SessionSetupReq_isUsed) {
        struct iso2_SessionSetupReqType *m = &b->SessionSetupReq;
        M("SessionSetupReq");
        emit(&o, ",\"evccid\":");
        emit_hex(&o, m->EVCCID.bytes, m->EVCCID.bytesLen);
    } else if (b->SessionSetupRes_isUsed) {
        struct iso2_SessionSetupResType *m = &b->SessionSetupRes;
        M("SessionSetupRes");
        emit(&o, ",\"response_code\":%d,\"evse_id\":", m->ResponseCode);
        emit_str(&o, m->EVSEID.characters, m->EVSEID.charactersLen);
        if (m->EVSETimeStamp_isUsed) emit(&o, ",\"datetime_now\":%lld", (long long)m->EVSETimeStamp);
    } else if (b->ServiceDiscoveryReq_isUsed) M("ServiceDiscoveryReq");
    else if (b->ServiceDiscoveryRes_isUsed) {
        struct iso2_ServiceDiscoveryResType *m = &b->ServiceDiscoveryRes;
        M("ServiceDiscoveryRes");
        emit(&o, ",\"response_code\":%d,\"payment_options\":\"", m->ResponseCode);
        for (int i = 0; i < m->PaymentOptionList.PaymentOption.arrayLen; i++)
            emit_name(&o, i, m->PaymentOptionList.PaymentOption.array[i], NAMES(PAYMENT_OPTION));
        emit(&o, "\",\"energy_transfer_modes\":\"");
        struct iso2_SupportedEnergyTransferModeType *t = &m->ChargeService.SupportedEnergyTransferMode;
        for (int i = 0; i < t->EnergyTransferMode.arrayLen; i++)
            emit_name(&o, i, t->EnergyTransferMode.array[i], NAMES(ISO2_ENERGY_TRANSFER));
        emit(&o, "\"");
    }
    else if (b->PaymentServiceSelectionReq_isUsed) { M("PaymentServiceSelectionReq"); emit(&o, ",\"selected_payment_option\":%d", b->PaymentServiceSelectionReq.SelectedPaymentOption); }
    else if (b->PaymentServiceSelectionRes_isUsed) { M("PaymentServiceSelectionRes"); emit(&o, ",\"response_code\":%d", b->PaymentServiceSelectionRes.ResponseCode); }
    else if (b->AuthorizationReq_isUsed) M("AuthorizationReq");
    else if (b->AuthorizationRes_isUsed) { M("AuthorizationRes"); emit(&o, ",\"response_code\":%d", b->AuthorizationRes.ResponseCode); }
    else if (b->ChargeParameterDiscoveryReq_isUsed) {
        struct iso2_ChargeParameterDiscoveryReqType *m = &b->ChargeParameterDiscoveryReq;
        M("ChargeParameterDiscoveryReq");
        emit(&o, ",\"requested_energy_transfer\":%d", m->RequestedEnergyTransferMode);
        if (m->DC_EVChargeParameter_isUsed) {
            struct iso2_DC_EVChargeParameterType *d = &m->DC_EVChargeParameter;
            ev_status_iso2(&o, &d->DC_EVStatus);
            emit(&o, ",\"ev_max_voltage\":%g,\"ev_max_current\":%g",
                 pv2(&d->EVMaximumVoltageLimit), pv2(&d->EVMaximumCurrentLimit));
            if (d->EVMaximumPowerLimit_isUsed) emit(&o, ",\"ev_max_power\":%g", pv2(&d->EVMaximumPowerLimit));
            if (d->EVEnergyCapacity_isUsed) emit(&o, ",\"ev_energy_capacity\":%g", pv2(&d->EVEnergyCapacity));
            if (d->FullSOC_isUsed) emit(&o, ",\"full_soc\":%d", d->FullSOC);
            if (d->BulkSOC_isUsed) emit(&o, ",\"bulk_soc\":%d", d->BulkSOC);
        }
    } else if (b->ChargeParameterDiscoveryRes_isUsed) {
        struct iso2_ChargeParameterDiscoveryResType *m = &b->ChargeParameterDiscoveryRes;
        M("ChargeParameterDiscoveryRes");
        emit(&o, ",\"response_code\":%d,\"evse_processing\":%d", m->ResponseCode, m->EVSEProcessing);
        if (m->DC_EVSEChargeParameter_isUsed) {
            struct iso2_DC_EVSEChargeParameterType *d = &m->DC_EVSEChargeParameter;
            evse_status_iso2(&o, &d->DC_EVSEStatus);
            emit(&o, ",\"evse_max_voltage\":%g,\"evse_max_current\":%g,\"evse_max_power\":%g,"
                     "\"evse_min_voltage\":%g,\"evse_min_current\":%g,\"evse_peak_current_ripple\":%g",
                 pv2(&d->EVSEMaximumVoltageLimit), pv2(&d->EVSEMaximumCurrentLimit),
                 pv2(&d->EVSEMaximumPowerLimit), pv2(&d->EVSEMinimumVoltageLimit),
                 pv2(&d->EVSEMinimumCurrentLimit), pv2(&d->EVSEPeakCurrentRipple));
            if (d->EVSECurrentRegulationTolerance_isUsed)
                emit(&o, ",\"evse_current_regulation_tolerance\":%g", pv2(&d->EVSECurrentRegulationTolerance));
            if (d->EVSEEnergyToBeDelivered_isUsed)
                emit(&o, ",\"evse_energy_to_be_delivered\":%g", pv2(&d->EVSEEnergyToBeDelivered));
        }
    } else if (b->CableCheckReq_isUsed) { M("CableCheckReq"); ev_status_iso2(&o, &b->CableCheckReq.DC_EVStatus); }
    else if (b->CableCheckRes_isUsed) { M("CableCheckRes"); emit(&o, ",\"response_code\":%d,\"evse_processing\":%d", b->CableCheckRes.ResponseCode, b->CableCheckRes.EVSEProcessing); evse_status_iso2(&o, &b->CableCheckRes.DC_EVSEStatus); }
    else if (b->PreChargeReq_isUsed) { M("PreChargeReq"); ev_status_iso2(&o, &b->PreChargeReq.DC_EVStatus); emit(&o, ",\"ev_target_voltage\":%g,\"ev_target_current\":%g", pv2(&b->PreChargeReq.EVTargetVoltage), pv2(&b->PreChargeReq.EVTargetCurrent)); }
    else if (b->PreChargeRes_isUsed) { M("PreChargeRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->PreChargeRes.ResponseCode, pv2(&b->PreChargeRes.EVSEPresentVoltage)); evse_status_iso2(&o, &b->PreChargeRes.DC_EVSEStatus); }
    else if (b->PowerDeliveryReq_isUsed) {
        struct iso2_PowerDeliveryReqType *m = &b->PowerDeliveryReq;
        M("PowerDeliveryReq");
        emit(&o, ",\"charge_progress\":%d", m->ChargeProgress);
        if (m->DC_EVPowerDeliveryParameter_isUsed) ev_status_iso2(&o, &m->DC_EVPowerDeliveryParameter.DC_EVStatus);
    }
    else if (b->PowerDeliveryRes_isUsed) {
        M("PowerDeliveryRes"); emit(&o, ",\"response_code\":%d", b->PowerDeliveryRes.ResponseCode);
        if (b->PowerDeliveryRes.DC_EVSEStatus_isUsed) evse_status_iso2(&o, &b->PowerDeliveryRes.DC_EVSEStatus);
    }
    else if (b->CurrentDemandReq_isUsed) {
        struct iso2_CurrentDemandReqType *m = &b->CurrentDemandReq;
        M("CurrentDemandReq");
        ev_status_iso2(&o, &m->DC_EVStatus);
        emit(&o, ",\"ev_target_voltage\":%g,\"ev_target_current\":%g,\"charging_complete\":%d",
             pv2(&m->EVTargetVoltage), pv2(&m->EVTargetCurrent), m->ChargingComplete);
        if (m->EVMaximumVoltageLimit_isUsed) emit(&o, ",\"ev_max_voltage\":%g", pv2(&m->EVMaximumVoltageLimit));
        if (m->EVMaximumCurrentLimit_isUsed) emit(&o, ",\"ev_max_current\":%g", pv2(&m->EVMaximumCurrentLimit));
        if (m->EVMaximumPowerLimit_isUsed) emit(&o, ",\"ev_max_power\":%g", pv2(&m->EVMaximumPowerLimit));
        if (m->BulkChargingComplete_isUsed) emit(&o, ",\"bulk_charging_complete\":%d", m->BulkChargingComplete);
        if (m->RemainingTimeToFullSoC_isUsed) emit(&o, ",\"remaining_time_to_full_soc\":%g", pv2(&m->RemainingTimeToFullSoC));
        if (m->RemainingTimeToBulkSoC_isUsed) emit(&o, ",\"remaining_time_to_bulk_soc\":%g", pv2(&m->RemainingTimeToBulkSoC));
    }
    else if (b->CurrentDemandRes_isUsed) {
        struct iso2_CurrentDemandResType *m = &b->CurrentDemandRes;
        M("CurrentDemandRes");
        emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_present_current\":%g,"
                 "\"evse_current_limit_achieved\":%d,\"evse_voltage_limit_achieved\":%d,"
                 "\"evse_power_limit_achieved\":%d",
             m->ResponseCode, pv2(&m->EVSEPresentVoltage), pv2(&m->EVSEPresentCurrent),
             m->EVSECurrentLimitAchieved, m->EVSEVoltageLimitAchieved, m->EVSEPowerLimitAchieved);
        evse_status_iso2(&o, &m->DC_EVSEStatus);
        if (m->EVSEMaximumVoltageLimit_isUsed) emit(&o, ",\"evse_max_voltage\":%g", pv2(&m->EVSEMaximumVoltageLimit));
        if (m->EVSEMaximumCurrentLimit_isUsed) emit(&o, ",\"evse_max_current\":%g", pv2(&m->EVSEMaximumCurrentLimit));
        if (m->EVSEMaximumPowerLimit_isUsed) emit(&o, ",\"evse_max_power\":%g", pv2(&m->EVSEMaximumPowerLimit));
    }
    else if (b->ChargingStatusReq_isUsed) M("ChargingStatusReq");
    else if (b->ChargingStatusRes_isUsed) { M("ChargingStatusRes"); emit(&o, ",\"response_code\":%d", b->ChargingStatusRes.ResponseCode); }
    else if (b->WeldingDetectionReq_isUsed) { M("WeldingDetectionReq"); ev_status_iso2(&o, &b->WeldingDetectionReq.DC_EVStatus); }
    else if (b->WeldingDetectionRes_isUsed) { M("WeldingDetectionRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->WeldingDetectionRes.ResponseCode, pv2(&b->WeldingDetectionRes.EVSEPresentVoltage)); evse_status_iso2(&o, &b->WeldingDetectionRes.DC_EVSEStatus); }
    else if (b->SessionStopReq_isUsed) { M("SessionStopReq"); emit(&o, ",\"charging_session\":%d", b->SessionStopReq.ChargingSession); }
    else if (b->SessionStopRes_isUsed) { M("SessionStopRes"); emit(&o, ",\"response_code\":%d", b->SessionStopRes.ResponseCode); }
    else M("Unknown");
    emit(&o, "}");
    return o.n;
}
