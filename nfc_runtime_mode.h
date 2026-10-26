// SPDX-License-Identifier: MIT
#ifndef NFC_RUNTIME_MODE_H
#define NFC_RUNTIME_MODE_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool general_webauthn;
    bool allow_localhost_browser;
    bool allow_pin_readonly;
    bool pin_session_preflight;
    bool pin_token_localhost;
    bool pin_compat_localhost;
    bool auto_localhost_continuous;
} nfc_runtime_mode_t;

// Accept only the supported general WebAuthn invocation.
bool nfc_runtime_mode_parse(int argc, char *const argv[], nfc_runtime_mode_t *out);
bool nfc_runtime_mode_should_stop(const nfc_runtime_mode_t *mode,
                                  int64_t elapsed_ms, bool stop_requested);
#endif
