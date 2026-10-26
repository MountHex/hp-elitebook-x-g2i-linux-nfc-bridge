// SPDX-License-Identifier: MIT
#include "nfc_recovery_policy.h"
// Result from NFC discovery: -2 means deliberate service stop; other
// unexpected outcomes stop the service without automatic polling retries.
int nfc_recovery_exit_code(int trigger_result) {
    return trigger_result == -2 ? 0 : NFC_RECOVERY_STOP_EXIT;
}
