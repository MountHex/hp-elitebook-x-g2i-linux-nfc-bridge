// SPDX-License-Identifier: MIT
#ifndef NFC_EVENT_PROTO_H
#define NFC_EVENT_PROTO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    NFC_NOTICE_FAMILY,
    NFC_NOTICE_ACK,
    NFC_NOTICE_DONE,
    NFC_NOTICE_TARGET_INFO,
    NFC_NOTICE_TARGETS_FOUND,
    NFC_NOTICE_TARGET_LOST,
    NFC_NOTICE_DEVICE_REMOVED
} nfc_notice_type_t;

typedef struct {
    nfc_notice_type_t type;
    uint32_t seq;
    int kernel_error;              // zero for successful ACK, positive errno otherwise
    uint16_t family;               // from controller response
    uint32_t group;                // resolved "events" group
    uint32_t device;
    uint32_t target;
    bool has_target;
    uint32_t protocols;              // from GET_TARGET dump, not card payload
} nfc_notice_t;

// Parse a complete generic-netlink datagram without reading out of bounds.
// "family" is zero until a successful controller lookup; then the resolved ID.
// Unknown commands are ignored. No card identifiers or payloads are exposed.
// Returns false on malformed framing or insufficient output capacity.
bool nfc_event_decode(const uint8_t *data, size_t len, uint16_t family,
                      nfc_notice_t *out, size_t cap, size_t *used);
#endif
