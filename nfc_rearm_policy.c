// SPDX-License-Identifier: MIT
#include "nfc_rearm_policy.h"
bool nfc_rearm_is_early(unsigned elapsed_ms, unsigned quiet_ms) {
    return quiet_ms == 0u || elapsed_ms < quiet_ms;
}
bool nfc_rearm_quiet_complete(unsigned elapsed_ms, unsigned quiet_ms,
                              bool any_target_event) {
    return quiet_ms != 0u && !nfc_rearm_is_early(elapsed_ms,quiet_ms) && !any_target_event;
}
