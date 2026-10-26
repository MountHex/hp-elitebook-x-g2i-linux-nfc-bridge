// SPDX-License-Identifier: MIT
#include "nfc_pin_session_policy.h"
#include <limits.h>

void nfc_pin_session_policy_clear(nfc_pin_session_policy_t *s) {
    if (!s) return;
    s->armed=false;
    s->deadline_ms=0;
}
bool nfc_pin_session_policy_arm_for(nfc_pin_session_policy_t *s, int64_t now_ms, int64_t hold_ms) {
    if (!s || now_ms<=0 || hold_ms<=0 || now_ms>INT64_MAX-hold_ms)
        return false;
    s->deadline_ms=now_ms+hold_ms;
    s->armed=true;
    return true;
}
bool nfc_pin_session_policy_arm(nfc_pin_session_policy_t *s, int64_t now_ms) {
    return nfc_pin_session_policy_arm_for(s,now_ms,NFC_PIN_PREFLIGHT_HOLD_MS);
}
bool nfc_pin_session_policy_valid(const nfc_pin_session_policy_t *s, int64_t now_ms) {
    return s && s->armed && now_ms>0 && now_ms<=s->deadline_ms;
}

/* Read-only CTAP status decision. The YubiKey still performs all verification. */
bool nfc_pin_assertion_retry_status(unsigned status) {
    if (status==0u || status>0xffu || status==0x2du) return false;
    if (status>=0x31u && status<=0x38u) return false;
    return status!=0x3cu && status!=0x3fu && status!=0x40u;
}
