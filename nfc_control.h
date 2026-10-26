// SPDX-License-Identifier: MIT
#ifndef NFC_CONTROL_H
#define NFC_CONTROL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>

// Injectable transport for generic-netlink protocol. No hardware access occurs
// when an external caller supplies a simulated netlink transport.
typedef struct {
    void *ctx;
    ssize_t (*send)(void *, const uint8_t *, size_t);
    ssize_t (*recv)(void *, uint8_t *, size_t, unsigned timeout_ms);
    int (*subscribe)(void *, uint32_t multicast_group);
    bool (*cancelled)(void *);
} nfc_nl_io_t;

typedef enum {
    NFC_CONTROL_OK = 0,
    NFC_CONTROL_ARGUMENT,
    NFC_CONTROL_TIMEOUT,
    NFC_CONTROL_CANCELLED,
    NFC_CONTROL_PROTOCOL,
    NFC_CONTROL_IO,
    NFC_CONTROL_KERNEL_ERROR
} nfc_control_result_t;

// Performs NFC generic-netlink family resolution, DEV_UP, START_POLL,
// TARGETS_FOUND event, then GET_TARGET dump. Bounded by total timeout.
// Does not perform DEV_DOWN or STOP_POLL on completion. Only the first
// matching ISO14443 target is selected; FIDO applet selection is separate.
nfc_control_result_t nfc_control_find_target(const nfc_nl_io_t *io,
    uint32_t device_index, unsigned timeout_ms, uint32_t *target_index);

// Real Linux implementation: may power up the controller and begin RF
// polling; does not persist configuration. Do not invoke from an offline test.
// Returns a caller-owned, connected AF_NFC SOCK_SEQPACKET descriptor or -1.
// errno is set to ETIMEDOUT / ECANCELED / EPROTO / kernel error as appropriate.
int nfc_control_open(uint32_t device_index, unsigned timeout_ms,
    const atomic_bool *cancelled_flag /* NULL means no cancellation */);

// Raw target socket creation, kept separate from generic-netlink discovery.
// Returns -1 with errno on failure.
int nfc_control_connect_target(uint32_t device_index, uint32_t target_index,
    unsigned timeout_ms, const atomic_bool *cancelled_flag);
const char *nfc_control_result_string(nfc_control_result_t r);
#endif
