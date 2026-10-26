// SPDX-License-Identifier: MIT
#ifndef NFC_PIN_SESSION_POLICY_H
#define NFC_PIN_SESSION_POLICY_H
#include <stdbool.h>
#include <stdint.h>

enum { NFC_PIN_PREFLIGHT_HOLD_MS = 12000, NFC_PIN_COMPAT_HOLD_MS = 45000 };

typedef struct {
    bool armed;
    int64_t deadline_ms;
} nfc_pin_session_policy_t;

/* Retain an activated NFC connection after getKeyAgreement and a successful
 * encrypted token response. Default read-only mode uses 12 seconds;
 * PIN compatibility mode uses 45 seconds per bounded stage. No session
 * survives cancellation, expiration, transport failure, or UHID teardown. */
bool nfc_pin_session_policy_arm_for(nfc_pin_session_policy_t *s, int64_t now_ms, int64_t hold_ms);
/* CTAP status codes are metadata only. Ordinary assertion errors may be
 * retried within the existing bounded NFC token session; PIN/UV failure,
 * cancellation, successful completion and unknown/empty statuses do not
 * carry a reusable session. This is a bridge lifecycle decision only. */
bool nfc_pin_assertion_retry_status(unsigned ctap_status);
void nfc_pin_session_policy_clear(nfc_pin_session_policy_t *s);
bool nfc_pin_session_policy_arm(nfc_pin_session_policy_t *s, int64_t now_ms);
bool nfc_pin_session_policy_valid(const nfc_pin_session_policy_t *s, int64_t now_ms);
#endif
