// SPDX-License-Identifier: MIT
#include "nfc_runtime_mode.h"
#include <string.h>

bool nfc_runtime_mode_parse(int argc, char *const argv[], nfc_runtime_mode_t *out) {
    if (!out || !argv || argc != 3 || !argv[0] || !argv[1] || !argv[2] ||
        strcmp(argv[1], "--auto-webauthn-continuous") != 0 ||
        strcmp(argv[2], "--allow-webauthn-auth-registration") != 0) return false;
    const nfc_runtime_mode_t production = {
        .general_webauthn = true,
        .allow_localhost_browser = true,
        .allow_pin_readonly = true,
        .pin_session_preflight = true,
        .pin_token_localhost = true,
        .pin_compat_localhost = true,
        .auto_localhost_continuous = true,
    };
    *out = production;
    return true;
}

bool nfc_runtime_mode_should_stop(const nfc_runtime_mode_t *mode,
                                  int64_t elapsed_ms, bool stop_requested) {
    if (!mode || elapsed_ms < 0 || stop_requested) return true;
    return !mode->auto_localhost_continuous;
}
