// SPDX-License-Identifier: MIT
#ifndef NFC_AUTH_LIFECYCLE_H
#define NFC_AUTH_LIFECYCLE_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* Timers are monotonic milliseconds, with 0 denoting "not started".
 * Atomic fields connect the synchronous main UHID loop with its joined
 * NFC exchange worker; the worker is never detached. This module owns no
 * payloads, RP names, credential identifiers, keys or PIN data. */
typedef struct {
    atomic_int_fast64_t first_ms;
    atomic_int_fast64_t last_activity_ms;
    atomic_int_fast64_t presence_assertion_ms;
    atomic_bool exchange_active;
} nfc_auth_lifecycle_t;

void nfc_auth_lifecycle_reset(nfc_auth_lifecycle_t *s);
void nfc_auth_lifecycle_begin(nfc_auth_lifecycle_t *s, int64_t now,
                              bool starts_fresh_auth_stage);
void nfc_auth_lifecycle_finish(nfc_auth_lifecycle_t *s, int64_t now,
                               bool successful_up_uv_assertion);
int64_t nfc_auth_lifecycle_first(const nfc_auth_lifecycle_t *s);
int64_t nfc_auth_lifecycle_qualifying_assertion(const nfc_auth_lifecycle_t *s);
bool nfc_auth_lifecycle_grace_expired(const nfc_auth_lifecycle_t *s,
                                     int64_t now, unsigned grace_ms);
#endif
