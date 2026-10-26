// SPDX-License-Identifier: MIT
#ifndef NFC_BROWSER_GATE_H
#define NFC_BROWSER_GATE_H
#include <stdbool.h>
// Explicit opt-in, disabled by default; only localhost RP CTAP2 operations.
void nfc_bridge_set_localhost_browser_enabled(bool enabled);
/* Read-only clientPIN (getPINRetries/getKeyAgreement), opt-in separately. */
void nfc_bridge_set_pin_readonly_enabled(bool enabled);
/* Expanded localhost authentication compatibility (explicit opt-in). */
void nfc_bridge_set_pin_compat_localhost_enabled(bool enabled);
/* Explicit FIDO2/U2F authentication and resident/non-resident registration policy. */
void nfc_bridge_set_general_webauthn_enabled(bool enabled);
#endif
