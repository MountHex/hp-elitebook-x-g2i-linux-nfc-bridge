// SPDX-License-Identifier: MIT
/* Metadata-only NFC request rejection diagnostics. */
#ifndef NFC_POLICY_REJECT_DIAG_H
#define NFC_POLICY_REJECT_DIAG_H
#include <stddef.h>
#include <stdint.h>

/* Internal status marker only. Not a CTAP status code or browser response. */
#define NFC_POLICY_REJECT_REASON "NFC bridge policy denied request"

/* Logs only HID command and first request byte (if present), never the request.
 * Prints occurrence 1 then each 64th rejection. Thread-safe, no clock I/O. */
void nfc_policy_reject_diag_emit(uint8_t hid_cmd,
                                 const uint8_t *request, size_t request_len);
#endif
