// SPDX-License-Identifier: MIT
#ifndef NFC_REARM_POLICY_H
#define NFC_REARM_POLICY_H
#include <stdbool.h>
#include <stdint.h>
// Operational quiet interval, NOT proof that a key has been physically removed.
#define NFC_REARM_QUIET_MS 2500u
#define NFC_REARM_HELD_MAX_MS 120000u
#define NFC_REARM_SELECT_PERIOD_MS 850u
#define NFC_REARM_MAX_SUPPRESSIONS 5u
// Suppress an early rediscovery after prior UHID cleanup; an event at exactly
// the boundary remains guarded unless the full interval has elapsed
// without any target event being decoded.
bool nfc_rearm_is_early(unsigned elapsed_ms, unsigned quiet_ms);
// Do not accept another key until a full quiet window without a target event.
bool nfc_rearm_quiet_complete(unsigned elapsed_ms, unsigned quiet_ms,
                              bool any_target_event);
#endif
