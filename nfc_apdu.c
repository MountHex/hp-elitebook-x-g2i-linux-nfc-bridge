// SPDX-License-Identifier: MIT
// Mirrors libfido2 1.17.0 native NFC APDU wire behaviour (not linked to libfido2).
// Intentionally excludes PC/SC, libfido2 internals, UHID and Linux netlink.
#define _POSIX_C_SOURCE 200809L
#include "nfc_apdu.h"
#include <limits.h>
#include <string.h>
#include <time.h>

#define RX_MAX 258u
#define MAX_APDU (5u + NFC_SHORT_CHUNK + 1u)
#define SW_OK 0x9000u
#define SW_UPDATE 0x9100u
#define NFC_ABORT_BUDGET_MS 100u
#define RX_CHAIN_LIMIT 64u

static uint64_t clock_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static unsigned remaining_ms(uint64_t end_ms) {
    uint64_t now = clock_ms();
    if (now == UINT64_MAX || now >= end_ms) return 0u;
    uint64_t remaining = end_ms - now;
    return remaining > UINT_MAX ? UINT_MAX : (unsigned)remaining;
}
static nfc_apdu_status_t state(const nfc_apdu_io_t *io, uint64_t end) {
    if (io->cancelled && io->cancelled(io->ctx)) return NFC_APDU_CANCELLED;
    if (!remaining_ms(end)) return NFC_APDU_TIMEOUT;
    return NFC_APDU_OK;
}
static nfc_apdu_status_t validate(const nfc_apdu_io_t *io, unsigned ms) {
    if (!ms || !io || !io->send_apdu || !io->recv_apdu) return NFC_APDU_BAD_ARGUMENT;
    return NFC_APDU_OK;
}
static nfc_apdu_status_t write_apdu(const nfc_apdu_io_t *io, const uint8_t *buf,
                                    size_t n, uint64_t end) {
    nfc_apdu_status_t r = state(io, end);
    if (r != NFC_APDU_OK) return r;
    if (io->send_apdu(io->ctx, buf, n, remaining_ms(end)) != (ssize_t)n)
        return state(io, end) == NFC_APDU_OK ? NFC_APDU_IO_ERROR : state(io, end);
    return state(io, end);
}
static nfc_apdu_status_t read_apdu(const nfc_apdu_io_t *io, uint8_t *buf,
                                   size_t cap, size_t *len, uint64_t end) {
    nfc_apdu_status_t r = state(io, end);
    if (r != NFC_APDU_OK) return r;
    ssize_t got = io->recv_apdu(io->ctx, buf, cap, remaining_ms(end));
    if (got < 0)
        return state(io, end) == NFC_APDU_OK ? NFC_APDU_IO_ERROR : state(io, end);
    if (got < 2 || (size_t)got > cap)
        return state(io, end) == NFC_APDU_OK ? NFC_APDU_BAD_RESPONSE : state(io, end);
    *len = (size_t)got;
    return state(io, end);
}
static unsigned sw(const uint8_t *buf, size_t n) {
    return ((unsigned)buf[n-2u] << 8u) | buf[n-1u];
}
static nfc_apdu_status_t send_chained(const nfc_apdu_io_t *io, uint8_t cla,
                                     uint8_t ins, uint8_t p1, uint8_t p2,
                                     const uint8_t *payload, size_t payload_len,
                                     uint64_t end) {
    uint8_t frame[MAX_APDU];
    uint8_t ack[RX_MAX];
    size_t offset = 0u;
    do {
        size_t chunk = payload_len - offset;
        if (chunk > NFC_SHORT_CHUNK) chunk = NFC_SHORT_CHUNK;
        bool more = payload_len - offset > chunk;
        frame[0] = (uint8_t)(cla | (more ? 0x10u : 0u));
        frame[1] = ins; frame[2] = p1; frame[3] = p2;
        frame[4] = (uint8_t)chunk;
        if (chunk) memcpy(frame + 5u, payload + offset, chunk);
        size_t frame_len = 5u + chunk;
        if (!more) frame[frame_len++] = 0x00u; // short Le
        nfc_apdu_status_t r = write_apdu(io, frame, frame_len, end);
        memset(frame, 0, sizeof(frame));
        if (r != NFC_APDU_OK) return r;
        if (more) {
            size_t ack_len = 0;
            r = read_apdu(io, ack, sizeof ack, &ack_len, end);
            if (r != NFC_APDU_OK) return r;
            if (sw(ack, ack_len) != SW_OK || ack_len != 2u)
                return NFC_APDU_CARD_ERROR;
        }
        offset += chunk;
    } while (offset < payload_len);
    return NFC_APDU_OK;
}
// Collects a status-word-terminated response, including any 61xx chaining.
static nfc_apdu_status_t receive_chained(const nfc_apdu_io_t *io, bool cbor,
                                         uint8_t *out, size_t cap,
                                         size_t *outlen, uint64_t end,
                                         bool *status_update) {
    uint8_t frame[RX_MAX];
    size_t total = 0u, frame_len = 0u;
    unsigned count = 0;
    if (status_update) *status_update = false;
    for (;;) {
        nfc_apdu_status_t r = read_apdu(io, frame, sizeof frame, &frame_len, end);
        if (r != NFC_APDU_OK) return r;
        const size_t body = frame_len - 2u;
        if (body > cap - total) return NFC_APDU_BUFFER_TOO_SMALL;
        if (body) memcpy(out + total, frame, body);
        total += body;
        if (frame[frame_len - 2u] != 0x61u) {
            unsigned code = sw(frame, frame_len);
            if (code == SW_UPDATE && status_update) {
                // A status update is precisely one processing/up-needed byte;
                // never forward it to the caller as the final CTAP response.
                if (total != 1u || (out[0] != 1u && out[0] != 2u))
                    return NFC_APDU_BAD_RESPONSE;
                *status_update = true;
                *outlen = total;
                return NFC_APDU_OK;
            }
            if (code != SW_OK) return NFC_APDU_CARD_ERROR;
            *outlen = total;
            return NFC_APDU_OK;
        }
        if (++count > RX_CHAIN_LIMIT) return NFC_APDU_BAD_RESPONSE;
        const uint8_t get_response[5] = {
            cbor ? 0x80u : 0x00u, 0xc0u, 0, 0, frame[frame_len - 1u]
        };
        r = write_apdu(io, get_response, sizeof get_response, end);
        if (r != NFC_APDU_OK) return r;
    }
}
nfc_apdu_status_t nfc_apdu_select(const nfc_apdu_io_t *io, unsigned timeout_ms) {
    nfc_apdu_status_t r = validate(io, timeout_ms);
    if (r != NFC_APDU_OK) return r;
    uint64_t start = clock_ms();
    if (start == UINT64_MAX || timeout_ms > UINT64_MAX - start) return NFC_APDU_TIMEOUT;
    uint64_t end = start + timeout_ms;
    const uint8_t aid[8] = {0xa0,0x00,0x00,0x06,0x47,0x2f,0x00,0x01};
    r = send_chained(io, 0x00, 0xa4, 0x04, 0x00, aid, sizeof aid, end);
    if (r != NFC_APDU_OK) return r;
    uint8_t version[64] = {0};
    size_t version_len = 0;
    r = receive_chained(io, false, version, sizeof version, &version_len, end, NULL);
    if (r != NFC_APDU_OK) return r;
    static const uint8_t v2[] = {'F','I','D','O','_','2','_','0'};
    static const uint8_t v1[] = {'U','2','F','_','V','2'};
    if ((version_len == sizeof v2 && memcmp(version,v2,sizeof v2)==0) ||
        (version_len == sizeof v1 && memcmp(version,v1,sizeof v1)==0))
        return NFC_APDU_OK;
    return NFC_APDU_BAD_RESPONSE;
}
// Called only after we have observed NFC 0x9100 for the active operation.
// The socket's normal send rejects cancellation; this one strictly bounded
// path is necessary to notify the physical token. Closing the session remains
// the fallback when it cannot be sent. No reply is required to clean up here.
static void best_effort_nfc_cancel(const nfc_apdu_io_t *io) {
    const uint8_t abort_apdu[5] = {0x80u, 0x11u, 0x11u, 0x00u, 0x00u};
    if (io->send_cancel_apdu)
        (void)io->send_cancel_apdu(io->ctx, abort_apdu, sizeof abort_apdu,
                                   NFC_ABORT_BUDGET_MS);
}

nfc_apdu_status_t nfc_apdu_cbor_with_progress(const nfc_apdu_io_t *io,
                               const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t cap, size_t *n,
                               unsigned timeout_ms,
                               nfc_apdu_progress_fn progress, void *progress_ctx) {
    if (n) *n = 0;
    nfc_apdu_status_t r = validate(io, timeout_ms);
    if (r != NFC_APDU_OK || !req || req_len == 0u || req_len > NFC_CTAPHID_MAX_PAYLOAD ||
        !resp || !n || cap == 0u) return NFC_APDU_BAD_ARGUMENT;
    uint64_t start = clock_ms();
    if (start == UINT64_MAX || timeout_ms > UINT64_MAX - start) return NFC_APDU_TIMEOUT;
    uint64_t end = start + timeout_ms;
    // Advertise NFCCTAP_GETRESPONSE support to the authenticator (P1=0x80).
    r = send_chained(io, 0x80u, 0x10u, 0x80u, 0x00u, req, req_len, end);
    if (r != NFC_APDU_OK) return r;
    bool seen_update = false;
    for (;;) {
        bool update = false;
        r = receive_chained(io, true, resp, cap, n, end, &update);
        if (r != NFC_APDU_OK) {
            if (seen_update && r == NFC_APDU_CANCELLED)
                best_effort_nfc_cancel(io);
            *n = 0;
            return r;
        }
        if (!update) {
            if (*n < 1u) { *n = 0; return NFC_APDU_BAD_RESPONSE; }
            // The physical token returned a final CTAP status and payload.
            return NFC_APDU_OK;
        }
        seen_update = true;
        uint8_t status = resp[0];
        *n = 0;
        if (progress) progress(progress_ctx, status);
        if (io->cancelled && io->cancelled(io->ctx)) {
            best_effort_nfc_cancel(io);
            return NFC_APDU_CANCELLED;
        }
        // Required promptly after 0x9100 (no artificial sleep); P1=0.
        const uint8_t followup[5] = {0x80u, 0x11u, 0x00u, 0x00u, 0x00u};
        r = write_apdu(io, followup, sizeof followup, end);
        if (r != NFC_APDU_OK) {
            if (r == NFC_APDU_CANCELLED) best_effort_nfc_cancel(io);
            return r;
        }
    }
}

nfc_apdu_status_t nfc_apdu_cbor(const nfc_apdu_io_t *io,
                               const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t cap, size_t *n,
                               unsigned timeout_ms) {
    return nfc_apdu_cbor_with_progress(io, req, req_len, resp, cap, n,
                                        timeout_ms, NULL, NULL);
}

// Raw U2F APDU transport: never rewrite CLA/INS or translate SW into
// CTAP2 status. An ISO7816 61xx response is read through GET RESPONSE;
// final status bytes are returned to the host as required for CTAPHID_MSG.
nfc_apdu_status_t nfc_apdu_u2f(const nfc_apdu_io_t *io,
    const uint8_t *req,size_t req_len,
    uint8_t *resp,size_t cap,size_t *n,unsigned timeout_ms) {
    if(n) *n=0u;
    if(validate(io,timeout_ms)!=NFC_APDU_OK || !req || !resp || !n ||
       req_len<5u || req_len>NFC_CTAPHID_MAX_PAYLOAD || cap<2u) return NFC_APDU_BAD_ARGUMENT;
    if(req[0]!=0x00u || req[3]!=0x00u ||
       (req[1]!=0x01u && req[1]!=0x02u && req[1]!=0x03u) ||
       (req[1]!=0x02u && req[2]!=0x00u) ||
       (req[1]==0x02u && req[2]!=0x03u && req[2]!=0x07u))
       return NFC_APDU_UNSUPPORTED;
    uint64_t start=clock_ms();
    if(start==UINT64_MAX||timeout_ms>UINT64_MAX-start) return NFC_APDU_TIMEOUT;
    uint64_t end=start+timeout_ms;
    nfc_apdu_status_t r=write_apdu(io,req,req_len,end);
    if(r!=NFC_APDU_OK) return r;
    uint8_t frame[RX_MAX];size_t frame_len=0,total=0;
    for(unsigned chunks=0;chunks<RX_CHAIN_LIMIT;chunks++) {
        r=read_apdu(io,frame,sizeof frame,&frame_len,end);
        if(r!=NFC_APDU_OK) return r;
        size_t body=frame_len-2u;
        if(body>cap-total) return NFC_APDU_BUFFER_TOO_SMALL;
        if(body) memcpy(resp+total,frame,body);
        total+=body;
        if(frame[frame_len-2u]!=0x61u) {
            if(cap-total<2u) return NFC_APDU_BUFFER_TOO_SMALL;
            resp[total++]=frame[frame_len-2u];
            resp[total++]=frame[frame_len-1u];
            *n=total;
            return NFC_APDU_OK;
        }
        const uint8_t next[5]={0x00u,0xc0u,0x00u,0x00u,frame[frame_len-1u]};
        r=write_apdu(io,next,sizeof next,end);
        if(r!=NFC_APDU_OK) return r;
    }
    return NFC_APDU_BAD_RESPONSE;
}

const char *nfc_apdu_status_string(nfc_apdu_status_t status) {
    switch (status) {
    case NFC_APDU_OK: return "ok";
    case NFC_APDU_BAD_ARGUMENT: return "bad argument";
    case NFC_APDU_UNSUPPORTED: return "unsupported command";
    case NFC_APDU_IO_ERROR: return "I/O failure";
    case NFC_APDU_TIMEOUT: return "timeout";
    case NFC_APDU_CANCELLED: return "cancelled";
    case NFC_APDU_BAD_RESPONSE: return "malformed response";
    case NFC_APDU_BUFFER_TOO_SMALL: return "response buffer too small";
    case NFC_APDU_CARD_ERROR: return "NFC card status error";
    default: return "unknown";
    }
}
