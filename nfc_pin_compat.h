// SPDX-License-Identifier: MIT
#ifndef NFC_PIN_COMPAT_H
#define NFC_PIN_COMPAT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef enum {
    NFC_COMPAT_REJECT=0,
    NFC_COMPAT_INFO,
    NFC_COMPAT_PIN_READ,
    NFC_COMPAT_PIN_AGREEMENT,
    NFC_COMPAT_PIN_TOKEN,
    NFC_COMPAT_ASSERTION,
    NFC_COMPAT_NEXT_ASSERTION
} nfc_compat_op_t;
typedef struct {
    nfc_compat_op_t op;
    unsigned ctap_command;
    unsigned pin_subcommand;
    unsigned pin_protocol;
    bool pin_authorized_assertion;
} nfc_compat_result_t;
/* Strict bounds, broad valid CBOR encodings. Never print/copy sensitive input. */
nfc_compat_result_t nfc_pin_compat_classify(const uint8_t *req,size_t n,const char *rp);
#endif
