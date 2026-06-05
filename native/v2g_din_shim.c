/* Thin shim over libcbv2g: decode a DIN 70121 V2G EXI message to a compact JSON
 * object of the telemetry-relevant fields. Returns bytes written (>0) or <0 on error.
 * Pure C; built into a self-contained shared library and called via Python ctypes. */
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

int v2g_din_decode_json(const uint8_t *data, int len, char *out, int cap) {
    exi_bitstream_t s;
    exi_bitstream_init(&s, (uint8_t *)data, (size_t)len, 0, NULL);
    struct din_exiDocument doc;
    int rc = decode_din_exiDocument(&s, &doc);
    if (rc != 0) return rc < 0 ? rc : -rc;
    struct din_BodyType *b = &doc.V2G_Message.Body;
    struct buf o = {out, cap, 0};

#define M(name) emit(&o, "{\"msg\":\"%s\"", name)
    if (b->SessionSetupReq_isUsed) {
        M("SessionSetupReq"); emit(&o, ",\"evccid\":\"");
        for (int i = 0; i < b->SessionSetupReq.EVCCID.bytesLen; i++) emit(&o, "%02x", b->SessionSetupReq.EVCCID.bytes[i]);
        emit(&o, "\"");
    } else if (b->SessionSetupRes_isUsed) {
        struct din_SessionSetupResType *m = &b->SessionSetupRes;
        M("SessionSetupRes");
        emit(&o, ",\"response_code\":%d,\"evse_id\":\"", m->ResponseCode);
        for (int i = 0; i < m->EVSEID.bytesLen; i++) emit(&o, "%02x", m->EVSEID.bytes[i]);
        emit(&o, "\",\"datetime_now\":%lld", (long long)m->DateTimeNow);
    }
    else if (b->ServiceDiscoveryReq_isUsed) M("ServiceDiscoveryReq");
    else if (b->ServiceDiscoveryRes_isUsed) { M("ServiceDiscoveryRes"); emit(&o, ",\"response_code\":%d", b->ServiceDiscoveryRes.ResponseCode); }
    else if (b->ServicePaymentSelectionReq_isUsed) M("ServicePaymentSelectionReq");
    else if (b->ServicePaymentSelectionRes_isUsed) { M("ServicePaymentSelectionRes"); emit(&o, ",\"response_code\":%d", b->ServicePaymentSelectionRes.ResponseCode); }
    else if (b->ContractAuthenticationReq_isUsed) M("ContractAuthenticationReq");
    else if (b->ContractAuthenticationRes_isUsed) { M("ContractAuthenticationRes"); emit(&o, ",\"response_code\":%d", b->ContractAuthenticationRes.ResponseCode); }
    else if (b->ChargeParameterDiscoveryReq_isUsed) {
        struct din_ChargeParameterDiscoveryReqType *m = &b->ChargeParameterDiscoveryReq;
        M("ChargeParameterDiscoveryReq");
        emit(&o, ",\"requested_energy_transfer\":%d", m->EVRequestedEnergyTransferType);
        if (m->DC_EVChargeParameter_isUsed) {
            struct din_DC_EVChargeParameterType *d = &m->DC_EVChargeParameter;
            emit(&o, ",\"soc\":%d,\"ev_max_voltage\":%g,\"ev_max_current\":%g",
                 d->DC_EVStatus.EVRESSSOC, pv(&d->EVMaximumVoltageLimit),
                 pv(&d->EVMaximumCurrentLimit));
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
            emit(&o, ",\"evse_max_voltage\":%g,\"evse_max_current\":%g,\"evse_max_power\":%g",
                 pv(&d->EVSEMaximumVoltageLimit), pv(&d->EVSEMaximumCurrentLimit),
                 pv(&d->EVSEMaximumPowerLimit));
        }
    }
    else if (b->CableCheckReq_isUsed) { M("CableCheckReq"); emit(&o, ",\"soc\":%d", b->CableCheckReq.DC_EVStatus.EVRESSSOC); }
    else if (b->CableCheckRes_isUsed) { M("CableCheckRes"); emit(&o, ",\"response_code\":%d,\"evse_processing\":%d,\"evse_status_code\":%d", b->CableCheckRes.ResponseCode, b->CableCheckRes.EVSEProcessing, b->CableCheckRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->PreChargeReq_isUsed) { M("PreChargeReq"); emit(&o, ",\"soc\":%d,\"ev_target_voltage\":%g,\"ev_target_current\":%g", b->PreChargeReq.DC_EVStatus.EVRESSSOC, pv(&b->PreChargeReq.EVTargetVoltage), pv(&b->PreChargeReq.EVTargetCurrent)); }
    else if (b->PreChargeRes_isUsed) { M("PreChargeRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_status_code\":%d", b->PreChargeRes.ResponseCode, pv(&b->PreChargeRes.EVSEPresentVoltage), b->PreChargeRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->PowerDeliveryReq_isUsed) M("PowerDeliveryReq");
    else if (b->PowerDeliveryRes_isUsed) { M("PowerDeliveryRes"); emit(&o, ",\"response_code\":%d", b->PowerDeliveryRes.ResponseCode); }
    else if (b->CurrentDemandReq_isUsed) { M("CurrentDemandReq"); emit(&o, ",\"soc\":%d,\"ev_target_voltage\":%g,\"ev_target_current\":%g,\"charging_complete\":%d", b->CurrentDemandReq.DC_EVStatus.EVRESSSOC, pv(&b->CurrentDemandReq.EVTargetVoltage), pv(&b->CurrentDemandReq.EVTargetCurrent), b->CurrentDemandReq.ChargingComplete); }
    else if (b->CurrentDemandRes_isUsed) { M("CurrentDemandRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_present_current\":%g,\"evse_status_code\":%d", b->CurrentDemandRes.ResponseCode, pv(&b->CurrentDemandRes.EVSEPresentVoltage), pv(&b->CurrentDemandRes.EVSEPresentCurrent), b->CurrentDemandRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->WeldingDetectionReq_isUsed) M("WeldingDetectionReq");
    else if (b->WeldingDetectionRes_isUsed) { M("WeldingDetectionRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->WeldingDetectionRes.ResponseCode, pv(&b->WeldingDetectionRes.EVSEPresentVoltage)); }
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
            emit(&o, ",\"protocol\":\"%.*s\",\"version_major\":%u,\"version_minor\":%u,\"schema_id\":%u",
                 (int)ap->ProtocolNamespace.charactersLen, ap->ProtocolNamespace.characters,
                 ap->VersionNumberMajor, ap->VersionNumberMinor, ap->SchemaID);
        }
        emit(&o, "}");
    } else if (doc.supportedAppProtocolRes_isUsed) {
        emit(&o, "{\"msg\":\"SupportedAppProtocolRes\",\"response_code\":%d,\"schema_id\":%u}",
             doc.supportedAppProtocolRes.ResponseCode, doc.supportedAppProtocolRes.SchemaID);
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
    struct iso2_BodyType *b = &doc.V2G_Message.Body;
    struct buf o = {out, cap, 0};

    if (b->SessionSetupReq_isUsed) {
        struct iso2_SessionSetupReqType *m = &b->SessionSetupReq;
        M("SessionSetupReq");
        emit(&o, ",\"evccid\":\"");
        for (int i = 0; i < m->EVCCID.bytesLen; i++) emit(&o, "%02x", m->EVCCID.bytes[i]);
        emit(&o, "\"");
    } else if (b->SessionSetupRes_isUsed) {
        struct iso2_SessionSetupResType *m = &b->SessionSetupRes;
        M("SessionSetupRes");
        emit(&o, ",\"response_code\":%d,\"evse_id\":\"%.*s\"", m->ResponseCode,
             (int)m->EVSEID.charactersLen, m->EVSEID.characters);
        if (m->EVSETimeStamp_isUsed) emit(&o, ",\"datetime_now\":%lld", (long long)m->EVSETimeStamp);
    } else if (b->ServiceDiscoveryReq_isUsed) M("ServiceDiscoveryReq");
    else if (b->ServiceDiscoveryRes_isUsed) { M("ServiceDiscoveryRes"); emit(&o, ",\"response_code\":%d", b->ServiceDiscoveryRes.ResponseCode); }
    else if (b->PaymentServiceSelectionReq_isUsed) M("PaymentServiceSelectionReq");
    else if (b->PaymentServiceSelectionRes_isUsed) { M("PaymentServiceSelectionRes"); emit(&o, ",\"response_code\":%d", b->PaymentServiceSelectionRes.ResponseCode); }
    else if (b->AuthorizationReq_isUsed) M("AuthorizationReq");
    else if (b->AuthorizationRes_isUsed) { M("AuthorizationRes"); emit(&o, ",\"response_code\":%d", b->AuthorizationRes.ResponseCode); }
    else if (b->ChargeParameterDiscoveryReq_isUsed) {
        struct iso2_ChargeParameterDiscoveryReqType *m = &b->ChargeParameterDiscoveryReq;
        M("ChargeParameterDiscoveryReq");
        emit(&o, ",\"requested_energy_transfer\":%d", m->RequestedEnergyTransferMode);
        if (m->DC_EVChargeParameter_isUsed) {
            struct iso2_DC_EVChargeParameterType *d = &m->DC_EVChargeParameter;
            emit(&o, ",\"soc\":%d,\"ev_max_voltage\":%g,\"ev_max_current\":%g",
                 d->DC_EVStatus.EVRESSSOC, pv2(&d->EVMaximumVoltageLimit), pv2(&d->EVMaximumCurrentLimit));
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
            emit(&o, ",\"evse_max_voltage\":%g,\"evse_max_current\":%g,\"evse_max_power\":%g",
                 pv2(&d->EVSEMaximumVoltageLimit), pv2(&d->EVSEMaximumCurrentLimit), pv2(&d->EVSEMaximumPowerLimit));
        }
    } else if (b->CableCheckReq_isUsed) { M("CableCheckReq"); emit(&o, ",\"soc\":%d", b->CableCheckReq.DC_EVStatus.EVRESSSOC); }
    else if (b->CableCheckRes_isUsed) { M("CableCheckRes"); emit(&o, ",\"response_code\":%d,\"evse_processing\":%d,\"evse_status_code\":%d", b->CableCheckRes.ResponseCode, b->CableCheckRes.EVSEProcessing, b->CableCheckRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->PreChargeReq_isUsed) { M("PreChargeReq"); emit(&o, ",\"soc\":%d,\"ev_target_voltage\":%g,\"ev_target_current\":%g", b->PreChargeReq.DC_EVStatus.EVRESSSOC, pv2(&b->PreChargeReq.EVTargetVoltage), pv2(&b->PreChargeReq.EVTargetCurrent)); }
    else if (b->PreChargeRes_isUsed) { M("PreChargeRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_status_code\":%d", b->PreChargeRes.ResponseCode, pv2(&b->PreChargeRes.EVSEPresentVoltage), b->PreChargeRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->PowerDeliveryReq_isUsed) M("PowerDeliveryReq");
    else if (b->PowerDeliveryRes_isUsed) { M("PowerDeliveryRes"); emit(&o, ",\"response_code\":%d", b->PowerDeliveryRes.ResponseCode); }
    else if (b->CurrentDemandReq_isUsed) { M("CurrentDemandReq"); emit(&o, ",\"soc\":%d,\"ev_target_voltage\":%g,\"ev_target_current\":%g,\"charging_complete\":%d", b->CurrentDemandReq.DC_EVStatus.EVRESSSOC, pv2(&b->CurrentDemandReq.EVTargetVoltage), pv2(&b->CurrentDemandReq.EVTargetCurrent), b->CurrentDemandReq.ChargingComplete); }
    else if (b->CurrentDemandRes_isUsed) { M("CurrentDemandRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g,\"evse_present_current\":%g,\"evse_status_code\":%d", b->CurrentDemandRes.ResponseCode, pv2(&b->CurrentDemandRes.EVSEPresentVoltage), pv2(&b->CurrentDemandRes.EVSEPresentCurrent), b->CurrentDemandRes.DC_EVSEStatus.EVSEStatusCode); }
    else if (b->ChargingStatusReq_isUsed) M("ChargingStatusReq");
    else if (b->ChargingStatusRes_isUsed) { M("ChargingStatusRes"); emit(&o, ",\"response_code\":%d", b->ChargingStatusRes.ResponseCode); }
    else if (b->WeldingDetectionReq_isUsed) M("WeldingDetectionReq");
    else if (b->WeldingDetectionRes_isUsed) { M("WeldingDetectionRes"); emit(&o, ",\"response_code\":%d,\"evse_present_voltage\":%g", b->WeldingDetectionRes.ResponseCode, pv2(&b->WeldingDetectionRes.EVSEPresentVoltage)); }
    else if (b->SessionStopReq_isUsed) M("SessionStopReq");
    else if (b->SessionStopRes_isUsed) { M("SessionStopRes"); emit(&o, ",\"response_code\":%d", b->SessionStopRes.ResponseCode); }
    else M("Unknown");
    emit(&o, "}");
    return o.n;
}
