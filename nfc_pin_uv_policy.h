// SPDX-License-Identifier: MIT
#ifndef NFC_PIN_UV_POLICY_H
#define NFC_PIN_UV_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* CTAP 2.1, PIN/UV protocol 1, getPinUvAuthTokenUsingPinWithPermissions.
 * Only getAssertion (0x02) permission for RP ID "localhost" is allowed.
 * No PIN bytes or encrypted PIN payload are logged by this parser. */
bool nfc_pin_uv_localhost_token_allowed(const uint8_t *req, size_t len);
/* Verifies a localhost getAssertion with a 16-byte protocol-1 auth param.
 * This is only eligible AFTER a successful restricted token response on the
 * same activated NFC connection; do not use as a standalone RP permission. */
bool nfc_pin_uv_localhost_assertion_allowed(const uint8_t *req, size_t len);
#endif
