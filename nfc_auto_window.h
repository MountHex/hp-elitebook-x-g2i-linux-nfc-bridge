// SPDX-License-Identifier: MIT
#ifndef NFC_AUTO_WINDOW_H
#define NFC_AUTO_WINDOW_H
#include <stdbool.h>
#include <stdint.h>
#define NFC_AUTO_INITIAL_MS 15000u
#define NFC_AUTO_ACTIVE_MS 30000u
// Evaluated BETWEEN synchronous UHID callbacks; no mid-command cancellation.
// auth_ms=0 means no approved localhost credential command has started.
bool nfc_auto_window_expired(int64_t now_ms, int64_t created_ms,
                             int64_t auth_ms, unsigned initial_ms,
                             unsigned active_ms);
#endif
