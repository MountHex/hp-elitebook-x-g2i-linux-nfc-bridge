// SPDX-License-Identifier: MIT
#include "nfc_auth_lifecycle.h"
#include <stddef.h>

void nfc_auth_lifecycle_reset(nfc_auth_lifecycle_t *s) {
    if (!s) return;
    atomic_store(&s->first_ms,0);
    atomic_store(&s->last_activity_ms,0);
    atomic_store(&s->presence_assertion_ms,0);
    atomic_store(&s->exchange_active,false);
}

void nfc_auth_lifecycle_begin(nfc_auth_lifecycle_t *s, int64_t now,
                              bool starts_fresh_auth_stage) {
    if (!s || now<=0) return;
    /* New PIN agreement/token/assertion can be another operation following
     * a successful prior assertion. Do not retire mid-PIN entry after one. */
    if (starts_fresh_auth_stage) atomic_store(&s->presence_assertion_ms,0);
    int64_t zero=0;
    (void)atomic_compare_exchange_strong(&s->first_ms,&zero,now);
    atomic_store(&s->exchange_active,true);
    atomic_store(&s->last_activity_ms,now);
}

void nfc_auth_lifecycle_finish(nfc_auth_lifecycle_t *s, int64_t now,
                               bool successful_up_uv_assertion) {
    if (!s || now<=0) return;
    atomic_store(&s->last_activity_ms,now);
    if (successful_up_uv_assertion)
        atomic_store(&s->presence_assertion_ms,now);
    atomic_store(&s->exchange_active,false);
}

int64_t nfc_auth_lifecycle_first(const nfc_auth_lifecycle_t *s) {
    return s ? atomic_load(&s->first_ms) : 0;
}

int64_t nfc_auth_lifecycle_qualifying_assertion(const nfc_auth_lifecycle_t *s) {
    return s ? atomic_load(&s->presence_assertion_ms) : 0;
}

bool nfc_auth_lifecycle_grace_expired(const nfc_auth_lifecycle_t *s,
                                     int64_t now, unsigned grace_ms) {
    if (!s || grace_ms==0 || now<=0 || atomic_load(&s->exchange_active)) return false;
    const int64_t qualifying=atomic_load(&s->presence_assertion_ms);
    const int64_t last=atomic_load(&s->last_activity_ms);
    if (qualifying<=0 || last<qualifying || now<last) return false;
    return now-last >= (int64_t)grace_ms;
}
