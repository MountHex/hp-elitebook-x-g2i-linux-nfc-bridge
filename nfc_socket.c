// SPDX-License-Identifier: MIT
// I/O for a PRE-CONNECTED Linux AF_NFC SOCK_SEQPACKET fd (not device discovery).
#define _GNU_SOURCE
#include "nfc_socket.h"
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static bool was_cancelled(void *p) {
    const nfc_socket_t *s = p;
    return s->cancel_flag && atomic_load(s->cancel_flag);
}
static int wait_fd_impl(nfc_socket_t *s, short events, unsigned ms, bool ignore_cancel) {
    uint64_t t = now_ms();
    if (t == UINT64_MAX) return -1;
    uint64_t end = t + ms;
    for (;;) {
        if (!ignore_cancel && was_cancelled(s)) return -1;
        t = now_ms();
        if (t == UINT64_MAX || t >= end) return -1;
        int slice = (int)((end - t) > 25u ? 25u : end - t);
        struct pollfd pfd = {.fd = s->fd, .events = events};
        int n = poll(&pfd, 1, slice);
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 || (n > 0 && (pfd.revents & (POLLERR|POLLHUP|POLLNVAL)))) return -1;
        if (n > 0 && (pfd.revents & events)) return 0;
    }
}
static ssize_t socket_send_impl(void *p, const uint8_t *buf, size_t n,
                                unsigned ms, bool ignore_cancel) {
    nfc_socket_t *s = p;
    if (wait_fd_impl(s, POLLOUT, ms, ignore_cancel) != 0 ||
        (!ignore_cancel && was_cancelled(s))) return -1;
    ssize_t rv = send(s->fd, buf, n, MSG_DONTWAIT|MSG_NOSIGNAL);
    return rv == (ssize_t)n ? rv : -1;
}
static ssize_t socket_send(void *p, const uint8_t *buf, size_t n, unsigned ms) {
    return socket_send_impl(p, buf, n, ms, false);
}
// Only for the protocol's one-shot NFCCTAP_GETRESPONSE cancellation APDU.
static ssize_t socket_send_cancel(void *p, const uint8_t *buf,
                                  size_t n, unsigned ms) {
    return socket_send_impl(p, buf, n, ms, true);
}
static ssize_t socket_recv(void *p, uint8_t *buf, size_t cap, unsigned ms) {
    nfc_socket_t *s = p;
    uint8_t response[1 + 258]; // Linux AF_NFC RX includes 0x00 leading status/preamble
    if (cap > 258u || wait_fd_impl(s, POLLIN, ms, false) != 0 || was_cancelled(s)) return -1;
    ssize_t rv = recv(s->fd, response, sizeof response, MSG_DONTWAIT|MSG_TRUNC);
    if (rv < 1 || rv > (ssize_t)(cap + 1u) || response[0] != 0u) {
        memset(response, 0, sizeof response);
        return -1;
    }
    size_t out = (size_t)rv - 1u;
    if (out) memcpy(buf, response + 1u, out);
    memset(response, 0, sizeof response);
    return (ssize_t)out;
}
nfc_apdu_io_t nfc_socket_io(nfc_socket_t *s) {
    return (nfc_apdu_io_t){.ctx=s,.send_apdu=socket_send,.recv_apdu=socket_recv,
                           .cancelled=was_cancelled,.send_cancel_apdu=socket_send_cancel};
}
