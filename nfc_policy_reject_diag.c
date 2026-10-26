// SPDX-License-Identifier: MIT
/* Rate-limited policy diagnostics; hardware exit-status 75 handling is separate. */
#include "nfc_policy_reject_diag.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>

static _Atomic uint_fast64_t rejected_requests;

void nfc_policy_reject_diag_emit(uint8_t hid_cmd,
                                 const uint8_t *request, size_t request_len) {
    const uint_fast64_t current =
        atomic_fetch_add_explicit(&rejected_requests, 1u,
                                  memory_order_relaxed) + 1u;
    if (current != 1u && (current % 64u) != 0u)
        return;
    if (request && request_len > 0u) {
        fprintf(stderr,
                "NFC_BRIDGE_POLICY_REJECT: unsupported request; hid=0x%02x "
                "request0=0x%02x; total=%" PRIuFAST64 " (sampled)\n",
                hid_cmd, request[0], current);
    } else {
        fprintf(stderr,
                "NFC_BRIDGE_POLICY_REJECT: unsupported request; hid=0x%02x "
                "request0=absent; total=%" PRIuFAST64 " (sampled)\n",
                hid_cmd, current);
    }
}
