// SPDX-License-Identifier: MIT
#ifndef NFC_LOCALHOST_POLICY_H
#define NFC_LOCALHOST_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// Compatibility policy: accept structurally valid CTAP2 makeCredential / getAssertion
// with RP "localhost", without any clientPIN/credentialManagement commands.
// No authenticity guarantees: caller/browser must enforce the real WebAuthn
// origin; this is only an additional narrow bridge-side policy restriction.
bool nfc_localhost_webauthn_allowed(const uint8_t *request, size_t request_len);
#endif
