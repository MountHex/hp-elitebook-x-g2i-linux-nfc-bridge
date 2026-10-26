// SPDX-License-Identifier: MIT
#ifndef NFC_AUTO_BRIDGE_EVENT_H
#define NFC_AUTO_BRIDGE_EVENT_H
#include <stdint.h>
#include <stdbool.h>
// Recorded for a policy-approved browser request, including read-only clientPIN;
// never logs payload or credential information.
void nfc_auto_bridge_event_reset(void);
int64_t nfc_auto_bridge_event_started_ms(void);
int64_t nfc_auto_bridge_event_user_present_ms(void);
bool nfc_auto_bridge_event_completion_grace_expired(int64_t now_ms,
                                                    unsigned grace_ms);
void nfc_bridge_set_pin_session_preflight_enabled(_Bool enabled);
/* Called by the single-threaded UHID loop when idle to enforce the 12s cap. */
void nfc_bridge_pin_session_expire(void);
void nfc_bridge_set_pin_token_localhost_enabled(_Bool enabled);
#endif
