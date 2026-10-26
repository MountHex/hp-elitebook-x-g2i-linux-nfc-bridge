// SPDX-License-Identifier: MIT
#ifndef HP_NFC_RECOVERY_POLICY_H
#define HP_NFC_RECOVERY_POLICY_H
// 75 (EX_TEMPFAIL) is designated a permanent stop for an NFC-trigger failure.
// The installed systemd unit uses RestartPreventExitStatus=75.
// This is NOT a physical-controller reset or an automatic recovery strategy.
#define NFC_RECOVERY_STOP_EXIT 75
int nfc_recovery_exit_code(int trigger_result);
#endif
