// SPDX-License-Identifier: MIT
#ifndef NFC_SOCKET_H
#define NFC_SOCKET_H
#include "nfc_apdu.h"
#include <stdatomic.h>
typedef struct {
    int fd; // caller owns already connected AF_NFC socket; this layer never closes it
    const atomic_bool *cancel_flag;
} nfc_socket_t;
nfc_apdu_io_t nfc_socket_io(nfc_socket_t *s);
#endif
