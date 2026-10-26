// SPDX-License-Identifier: MIT
#include "nfc_auto_window.h"
#include <stdint.h>
bool nfc_auto_window_expired(int64_t now_ms, int64_t created_ms,
                             int64_t auth_ms, unsigned initial_ms,
                             unsigned active_ms) {
    if (now_ms < 0 || created_ms < 0 || initial_ms == 0 || active_ms == 0 ||
        now_ms < created_ms) return true;
    if (auth_ms <= 0) return now_ms-created_ms >= (int64_t)initial_ms;
    if (auth_ms < created_ms || auth_ms > now_ms) return true;
    return now_ms-auth_ms >= (int64_t)active_ms;
}
