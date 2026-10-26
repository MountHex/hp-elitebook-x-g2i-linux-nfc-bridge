// SPDX-License-Identifier: MIT
#ifndef NFC_GENERAL_WEBAUTHN_H
#define NFC_GENERAL_WEBAUTHN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define NFC_GENERAL_RP_CAP 254u
typedef enum {
    NFC_GENERAL_REJECT=0, NFC_GENERAL_INFO, NFC_GENERAL_PIN_READ,
    NFC_GENERAL_PIN_AGREEMENT, NFC_GENERAL_PIN_TOKEN,
    NFC_GENERAL_ASSERTION, NFC_GENERAL_REGISTRATION, NFC_GENERAL_NEXT_ASSERTION
} nfc_general_op_t;
typedef struct {
    nfc_general_op_t op;
    unsigned ctap_command, pin_subcommand, pin_protocol;
    unsigned permissions; /* 0x01 makeCredential, 0x02 getAssertion */
    bool pin_authorized;
    bool pin_token_has_rp;
    char rp[NFC_GENERAL_RP_CAP]; /* per-request ephemeral RP for stage binding; NEVER logged */
} nfc_general_request_t;
// Structural bounded CTAP2 reader; does not replace browser origin verification.
// Does not enable PIN modification, reset or credential management.
nfc_general_request_t nfc_general_classify(const uint8_t *req,size_t length);
#endif
