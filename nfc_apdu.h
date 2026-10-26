// SPDX-License-Identifier: MIT
// Independent proof-of-concept for CTAP2-over-NFC APDU handling.
// No device discovery, PINs, credentials, or direct hardware opening.
#ifndef NFC_APDU_H
#define NFC_APDU_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define NFC_CTAPHID_MAX_PAYLOAD 7609u
#define NFC_SHORT_CHUNK 240u

// Link I/O sends one complete APDU and receives one complete APDU response.
// Callback success returns count, error returns -1. Timeout is bounded.
typedef struct {
    void *ctx;
    ssize_t (*send_apdu)(void *, const uint8_t *, size_t, unsigned);
    ssize_t (*recv_apdu)(void *, uint8_t *, size_t, unsigned);
    bool (*cancelled)(void *);
    // Optional escape hatch: send one NFCCTAP_GETRESPONSE CANCEL even when
    // cancelled() is true. Must be short/bounded; no retries or PIN data.
    ssize_t (*send_cancel_apdu)(void *, const uint8_t *, size_t, unsigned);
} nfc_apdu_io_t;

typedef enum {
    NFC_APDU_OK = 0,
    NFC_APDU_BAD_ARGUMENT,
    NFC_APDU_UNSUPPORTED,
    NFC_APDU_IO_ERROR,
    NFC_APDU_TIMEOUT,
    NFC_APDU_CANCELLED,
    NFC_APDU_BAD_RESPONSE,
    NFC_APDU_BUFFER_TOO_SMALL,
    NFC_APDU_CARD_ERROR
} nfc_apdu_status_t;

// Selects FIDO applet and accepts FIDO_2_0 or U2F_V2 identification.
nfc_apdu_status_t nfc_apdu_select(const nfc_apdu_io_t *io, unsigned timeout_ms);

// CTAPHID CBOR. Output includes CTAP status byte;
// no trailing NFC 90 00 word. CTAP errors are normal output, not I/O errors.
nfc_apdu_status_t nfc_apdu_cbor(const nfc_apdu_io_t *io,
    const uint8_t *request, size_t request_len,
    uint8_t *response, size_t response_cap, size_t *response_len,
    unsigned timeout_ms);

// Optional progress callback for NFC 0x9100 status updates (1 = processing,
// 2 = user presence needed). Callback must not block; subsequent GETRESPONSE
// must be sent promptly. The basic API remains source-compatible.
typedef void (*nfc_apdu_progress_fn)(void *ctx, uint8_t status);
nfc_apdu_status_t nfc_apdu_cbor_with_progress(const nfc_apdu_io_t *io,
    const uint8_t *request, size_t request_len,
    uint8_t *response, size_t response_cap, size_t *response_len,
    unsigned timeout_ms, nfc_apdu_progress_fn progress, void *progress_ctx);

// CTAPHID_MSG carries a complete legacy U2F APDU, not a CTAP2 CBOR command.
// This is the distinct NFC ISO7816 path. Return status words intact,
// including U2F check-only/user-presence statuses such as 0x6985.
// Raw response and APDU payloads must NEVER be logged.
nfc_apdu_status_t nfc_apdu_u2f(const nfc_apdu_io_t *io,
    const uint8_t *request,size_t request_len,
    uint8_t *response,size_t response_cap,size_t *response_len,
    unsigned timeout_ms);

const char *nfc_apdu_status_string(nfc_apdu_status_t status);
#endif
