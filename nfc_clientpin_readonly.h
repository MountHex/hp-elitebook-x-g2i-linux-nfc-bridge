// SPDX-License-Identifier: MIT
#ifndef NFC_CLIENTPIN_READONLY_H
#define NFC_CLIENTPIN_READONLY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Strict exact-shape CTAP2 authenticatorClientPIN allowlist:
 * getPINRetries (0x01) and getKeyAgreement (0x02) using protocol 1 only.
 * No PIN authentication, retries decrement, UV token, or mutating requests. */
bool nfc_clientpin_readonly_allowed(const uint8_t *request, size_t len);
#endif
