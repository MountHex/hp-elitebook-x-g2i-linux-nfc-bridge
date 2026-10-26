// SPDX-License-Identifier: MIT
// Native NFC implementation of the pcsc-fido bridge ABI.
// Supports normal browser WebAuthn/FIDO2 and U2F authentication.
#define _POSIX_C_SOURCE 200809L
#include "nfc_policy_reject_diag.h"
#include "nfc_control.h"
#include "nfc_apdu.h"
#include "nfc_socket.h"
#include "nfc_localhost_policy.h"
#include "nfc_browser_gate.h"
#include "nfc_clientpin_readonly.h"
#include "nfc_pin_session_policy.h"
#include "nfc_pin_uv_policy.h"
#include "nfc_pin_compat.h"
#include "nfc_general_webauthn.h"
#include "nfc_auto_bridge_event.h"
#include "nfc_auth_lifecycle.h"
#include <time.h>
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/pcsc_bridge.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef NFC_BRIDGE_DISCOVER_TIMEOUT_MS
#define NFC_BRIDGE_DISCOVER_TIMEOUT_MS 10000u
#endif
#ifndef NFC_BRIDGE_SELECT_TIMEOUT_MS
#define NFC_BRIDGE_SELECT_TIMEOUT_MS 3000u
#endif
#ifndef NFC_BRIDGE_EXCHANGE_TIMEOUT_MS
#define NFC_BRIDGE_EXCHANGE_TIMEOUT_MS 3000u
#endif
#ifndef NFC_BRIDGE_SELECTION_TIMEOUT_MS
#define NFC_BRIDGE_SELECTION_TIMEOUT_MS 20000u
#endif
#ifndef NFC_BRIDGE_REGISTRATION_TIMEOUT_MS
#define NFC_BRIDGE_REGISTRATION_TIMEOUT_MS 30000u
#endif

static atomic_bool cancel_requested = false;
static atomic_bool active = false;
static atomic_bool localhost_browser_enabled = false;
static atomic_bool pin_readonly_enabled = false;
static atomic_bool pin_session_preflight_enabled = false;
static atomic_bool pin_token_localhost_enabled = false;
static atomic_bool pin_compat_localhost_enabled = false;
static atomic_bool general_webauthn_enabled = false;
/* PIN-token requested RP binding, restricted to the lifetime of the retained
 * NFC socket. Cleared on all closure/reset paths. Never written to logs. */
static char token_scope_rp[NFC_GENERAL_RP_CAP];
static unsigned token_scope_permissions = 0u;
// Stateful authenticatorGetNextAssertion: requests after the first successful
// getAssertion must reuse the same activated physical NFC session.
// Never log credential IDs or returned user identities.
static unsigned next_assertions_pending = 0u;
static bool valid_legacy_u2f(const uint8_t *p,size_t n) {
    return p && n>=5u && n<=NFC_CTAPHID_MAX_PAYLOAD &&
           p[0]==0u && p[3]==0u &&
           (p[1]==1u || p[1]==2u || p[1]==3u) &&
           (p[1]==2u ? (p[2]==3u||p[2]==7u) : p[2]==0u);
}
static unsigned count_additional_assertions(const uint8_t *p,size_t n) {
    size_t at=1u,pairs=0u;
    if(!p||n<2u||p[0]!=0u||
       !pcsc_fido_cbor_read_type_len(p,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||pairs>32u)
       return 0u;
    for(size_t i=0;i<pairs;i++) {
        size_t key=0u,count=0u;
        if(!pcsc_fido_cbor_read_uint_value(p,n,&at,&key))return 0u;
        if(key==5u) {
            if(!pcsc_fido_cbor_read_uint_value(p,n,&at,&count) || count<2u || count>1024u)
                return 0u;
            return (unsigned)(count-1u);
        }
        if(!pcsc_fido_cbor_skip_item(p,n,&at))return 0u;
    }
    return 0u;
}

/* Only the single-threaded UHID event loop owns this fd. The held
 * connection belongs to one explicitly enabled, bounded NFC/PIN session.
 * It never survives UHID destruction, cancellation or session reset. */
static int pin_held_fd = -1;
/* 1: awaiting PIN token or old read-only follow-up; 2: PIN token obtained,
 * awaiting one or more bounded localhost assertion attempts. */
static unsigned pin_held_stage = 0u;
static nfc_pin_session_policy_t pin_policy = {0};
static int64_t pin_clock_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)!=0) return -1;
    return (int64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}
static bool compat_enabled(void) {
    return atomic_load_explicit(&pin_compat_localhost_enabled,memory_order_acquire);
}
static bool pin_arm(void) {
    const int64_t now=pin_clock_ms();
    return compat_enabled()
        ? nfc_pin_session_policy_arm_for(&pin_policy,now,NFC_PIN_COMPAT_HOLD_MS)
        : nfc_pin_session_policy_arm(&pin_policy,now);
}
/* Reads only the UP/UV bits from CTAP2 authenticatorData (CBOR key 2).
 * This is diagnostic metadata from the YubiKey response; signature validation
 * remains the responsibility of the relying party. Never print raw CBOR. */
static bool log_assertion_flags(const uint8_t *r, size_t n) {
    size_t at=1u,pairs=0u;
    if (!r || n<2u || r[0]!=0u ||
        !pcsc_fido_cbor_read_type_len(r,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) ||
        pairs>32u) goto unavailable;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0u;
        if(!pcsc_fido_cbor_read_uint_value(r,n,&at,&k)) goto unavailable;
        if(k==2u) {
            size_t data_len=0u;
            if(!pcsc_fido_cbor_read_type_len(r,n,&at,PCSC_FIDO_CBOR_MAJOR_BYTES,&data_len) ||
                data_len<37u || data_len>n-at) goto unavailable;
            unsigned flags=r[at+32u];
            fprintf(stderr,"ASSERTION_FLAGS: up=%u uv=%u\n",
                    (flags&0x01u)?1u:0u,(flags&0x04u)?1u:0u);
            return (flags&0x05u)==0x05u; /* UP=1 AND UV=1 */
        }
        if(!pcsc_fido_cbor_skip_item(r,n,&at)) goto unavailable;
    }
unavailable:
    fputs("ASSERTION_FLAGS: unavailable\n",stderr);
    return false;
}

/* A single successful CTAP assertion is NOT a browser-completion signal.
 * Some clients issue another PIN-authorised getAssertion immediately. */
bool pcsc_fido_bridge_auth_continuation_pending(void) {
    return pin_held_fd>=0 &&
           ((compat_enabled() && pin_held_stage==2u) ||
            (atomic_load_explicit(&general_webauthn_enabled,memory_order_acquire) &&
             next_assertions_pending>0u && (pin_held_stage==2u||pin_held_stage==3u))) &&
           nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms());
}

static void pin_held_close(void) {
    if (pin_held_fd>=0) (void)close(pin_held_fd);
    pin_held_fd=-1;
    pin_held_stage=0u;
    next_assertions_pending=0u;
    memset(token_scope_rp,0,sizeof token_scope_rp);
    token_scope_permissions=0u;
    nfc_pin_session_policy_clear(&pin_policy);
}
void nfc_bridge_pin_session_expire(void) {
    if (pin_held_fd>=0 && !nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms())) {
        const bool c=compat_enabled();
        pin_held_close();
        puts(c ? "PIN_COMPAT_SESSION_EXPIRED: held NFC connection closed." :
                 "PIN_PREFLIGHT_EXPIRED: read-only NFC connection closed.");
        fflush(stdout);
    }
}

static nfc_auth_lifecycle_t browser_lifecycle = {0};

void nfc_auto_bridge_event_reset(void) {
    nfc_auth_lifecycle_reset(&browser_lifecycle);
}
int64_t nfc_auto_bridge_event_started_ms(void) {
    return nfc_auth_lifecycle_first(&browser_lifecycle);
}
int64_t nfc_auto_bridge_event_user_present_ms(void) {
    return nfc_auth_lifecycle_qualifying_assertion(&browser_lifecycle);
}
bool nfc_auto_bridge_event_completion_grace_expired(int64_t now_ms,
                                                    unsigned grace_ms) {
    return nfc_auth_lifecycle_grace_expired(&browser_lifecycle,now_ms,grace_ms);
}
static void mark_browser_auth_start(bool fresh_auth_stage) {
    nfc_auth_lifecycle_begin(&browser_lifecycle,pin_clock_ms(),fresh_auth_stage);
}


void nfc_bridge_set_localhost_browser_enabled(bool enabled) {
    atomic_store_explicit(&localhost_browser_enabled, enabled, memory_order_release);
}

void nfc_bridge_set_pin_readonly_enabled(bool enabled) {
    atomic_store_explicit(&pin_readonly_enabled,enabled,memory_order_release);
}
void nfc_bridge_set_pin_session_preflight_enabled(bool enabled) {
    if (!enabled) pin_held_close();
    atomic_store_explicit(&pin_session_preflight_enabled,enabled,memory_order_release);
}

void nfc_bridge_set_pin_token_localhost_enabled(bool enabled) {
    if (!enabled) pin_held_close();
    atomic_store_explicit(&pin_token_localhost_enabled,enabled,memory_order_release);
}

void nfc_bridge_set_pin_compat_localhost_enabled(bool enabled) {
    if (!enabled) pin_held_close();
    atomic_store_explicit(&pin_compat_localhost_enabled,enabled,memory_order_release);
}


void nfc_bridge_set_general_webauthn_enabled(bool enabled) {
    if (!enabled) pin_held_close();
    atomic_store_explicit(&general_webauthn_enabled,enabled,memory_order_release);
}


static void set_error(char *err, size_t cap, const char *msg) {
    if (err && cap) (void)snprintf(err,cap,"%s", msg);
}

bool pcsc_fido_bridge_exchange(const char *reader_needle, uint8_t cmd,
    const uint8_t *request, size_t request_len,
    uint8_t *reply, size_t reply_cap, size_t *reply_len,
    char *err, size_t errcap) {
    (void)reader_needle;
    if (reply_len) *reply_len = 0;
    if (err && errcap) err[0] = '\0';
    // General browser authentication and narrowly enabled localhost
    // compatibility share the same request policy. Disallowed CTAP
    // management operations must still be refused.
    const bool general=atomic_load_explicit(&general_webauthn_enabled,memory_order_acquire);
    /* General CTAP requests use a bounded structural policy parser. */
    const nfc_general_request_t web=general ? nfc_general_classify(request,request_len)
                                               : (nfc_general_request_t){0};
    const bool generic_read=general && web.op==NFC_GENERAL_PIN_READ;
    const bool generic_agreement=general && web.op==NFC_GENERAL_PIN_AGREEMENT;
    const bool generic_token=general && web.op==NFC_GENERAL_PIN_TOKEN;
    const bool generic_assertion=general && web.op==NFC_GENERAL_ASSERTION;
    const bool generic_registration=general && web.op==NFC_GENERAL_REGISTRATION;
    const bool generic_next=general && web.op==NFC_GENERAL_NEXT_ASSERTION;
    const bool generic_u2f=general && cmd==PCSC_FIDO_HID_CMD_MSG && valid_legacy_u2f(request,request_len);
    const bool generic_info=general && web.op==NFC_GENERAL_INFO;
    const bool no_params = request && request_len == 1u &&
        (request[0] == 0x04u || request[0] == 0x0bu);
    const bool compat = compat_enabled();
    const bool localhost_browser_request = request && (!compat || request[0] != 0x01u) &&
        atomic_load_explicit(&localhost_browser_enabled, memory_order_acquire) &&
        nfc_localhost_webauthn_allowed(request,request_len);
    const bool pin_readonly_request = request &&
        atomic_load_explicit(&localhost_browser_enabled,memory_order_acquire) &&
        atomic_load_explicit(&pin_readonly_enabled,memory_order_acquire) &&
        nfc_clientpin_readonly_allowed(request,request_len);
    const bool token_mode=atomic_load_explicit(&pin_token_localhost_enabled,memory_order_acquire);
    const bool pin_token_request=request && token_mode &&
        atomic_load_explicit(&localhost_browser_enabled,memory_order_acquire) &&
        nfc_pin_uv_localhost_token_allowed(request,request_len);
    const bool verified_assertion=request && token_mode &&
        atomic_load_explicit(&localhost_browser_enabled,memory_order_acquire) &&
        nfc_pin_uv_localhost_assertion_allowed(request,request_len);
    const nfc_compat_result_t parsed = compat && !general ?
        nfc_pin_compat_classify(request,request_len,"localhost") : (nfc_compat_result_t){0};
    const bool compat_read = parsed.op==NFC_COMPAT_PIN_READ;
    const bool compat_agreement = parsed.op==NFC_COMPAT_PIN_AGREEMENT;
    const bool compat_token = parsed.op==NFC_COMPAT_PIN_TOKEN;
    const bool compat_assertion = parsed.op==NFC_COMPAT_ASSERTION;
    const bool compat_info = parsed.op==NFC_COMPAT_INFO;
    /* NextAssertion has no RP field: block until an explicit scoped
     * outstanding-assertions state machine exists. */
    const bool compat_next = false;
    if(generic_next && (next_assertions_pending==0u || pin_held_fd<0 ||
       (pin_held_stage!=2u && pin_held_stage!=3u) ||
       !nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms()))) {
        set_error(err,errcap,"nextAssertion requires live matching prior assertion");
        return false;
    }
    /* PIN token or PIN-authorised assertion requires a live matching stage.
     * Non-PIN assertions follow the general browser policy. */
    if (general && (generic_token ||
        ((generic_assertion || generic_registration) && web.pin_authorized)) &&
        (pin_held_fd<0 || pin_held_stage!=(generic_token?1u:2u) ||
         !nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms()))) {
        set_error(err,errcap,"restricted PIN session: live context required");
        return false;
    }
    if (general && (generic_assertion || generic_registration) &&
        web.pin_authorized && pin_held_stage==2u &&
        ((token_scope_permissions && !(token_scope_permissions &
            (generic_registration ? 1u : 2u))) ||
         (token_scope_rp[0] && strcmp(token_scope_rp,web.rp)!=0))) {
        set_error(err,errcap,"PIN token scoped to different RP or permission");
        return false;
    }
    if ((pin_token_request || verified_assertion || compat_token ||
         (compat_assertion && parsed.pin_authorized_assertion)) &&
        (pin_held_fd<0 || pin_held_stage!=((pin_token_request || compat_token)?1u:2u) ||
         !nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms()))) {
        if (compat) {
            const char *reason=pin_held_fd<0 ? "no-held-fd" :
                (pin_held_stage!=((pin_token_request || compat_token)?1u:2u)) ? "stage-mismatch" : "expired";
            fprintf(stderr,"PIN_COMPAT_SESSION_REJECT: ctap=0x%02x sub=0x%02x protocol=%u reason=%s\n",
                    parsed.ctap_command,parsed.pin_subcommand,parsed.pin_protocol,reason);
        }
        set_error(err,errcap,"restricted PIN session: matching live NFC context required");
        return false;
    }
    /* Keep all rejection decisions unchanged. A caller-owned output buffer
     * error is not a CTAP policy refusal, and must stay distinguishable. */
    if (!reply || !reply_len || reply_cap < 2u) {
        set_error(err,errcap,"invalid NFC response buffer");
        return false;
    }
    if ((!generic_u2f && cmd != PCSC_FIDO_HID_CMD_CBOR) ||
        (!generic_u2f && !no_params && !localhost_browser_request && !pin_readonly_request &&
         !pin_token_request && !verified_assertion && !compat_read &&
         !compat_agreement && !compat_token && !compat_assertion && !compat_info && !compat_next &&
         !generic_read && !generic_agreement && !generic_token && !generic_assertion &&
         !generic_registration && !generic_info && !generic_next)) {
        /* Log only bounded metadata; never print the CTAP payload or PIN.
         * The handler recognises this fixed status and avoids a duplicate. */
        nfc_policy_reject_diag_emit(cmd, request, request_len);
        set_error(err,errcap,NFC_POLICY_REJECT_REASON);
        return false;
    }
    if (generic_u2f) fputs("U2F_ALLOWED: legacy U2F command accepted; payload not logged.\n",stderr);
    if (general && web.op!=NFC_GENERAL_REJECT)
        fprintf(stderr,"CTAP_ALLOWED: ctap=0x%02x sub=0x%02x protocol=%u\n",
                web.ctap_command,web.pin_subcommand,web.pin_protocol);
    if (compat && parsed.op!=NFC_COMPAT_REJECT)
        fprintf(stderr,"PIN_COMPAT_ALLOWED: ctap=0x%02x sub=0x%02x protocol=%u\n",
                parsed.ctap_command,parsed.pin_subcommand,parsed.pin_protocol);
    if (atomic_exchange_explicit(&active,true,memory_order_acq_rel)) {
        set_error(err,errcap,"NFC exchange already in progress");
        return false;
    }
    const bool tracked_browser_auth = generic_read || generic_agreement ||
        generic_token || generic_assertion || generic_registration || generic_next || generic_u2f || generic_info ||
        localhost_browser_request || pin_readonly_request ||
        pin_token_request || verified_assertion || compat_read || compat_agreement ||
        compat_token || compat_assertion || compat_info;
    if (tracked_browser_auth)
        mark_browser_auth_start(compat_agreement || compat_token || compat_assertion ||
                                generic_agreement || generic_token || generic_assertion ||
                                generic_registration || generic_u2f);
    bool qualifies_for_early_cleanup=false;
    bool ok=false;
    int fd=-1;
    bool reused_pin_fd=false;
    bool keep_pin_fd=false;
    const bool preflight=atomic_load_explicit(&pin_session_preflight_enabled,memory_order_acquire);
    const bool pin_retries=generic_read || compat_read || (pin_readonly_request &&
        (request_len == 4u || request[request_len-1u] == 0x01u));
    const bool pin_agreement=generic_agreement || compat_agreement || (pin_readonly_request && !pin_retries);
    unsigned reused_stage=0u;
    unsigned ctap_status=0x100u;
    nfc_apdu_status_t result=NFC_APDU_BAD_RESPONSE;
    if (atomic_load(&cancel_requested)) {
        set_error(err,errcap,"cancelled before NFC connection");
        goto out;
    }
    /* Legacy preflight: same socket for read-only retries. Explicit localhost
     * PIN-token mode: only valid scoped token after agreement, then one
     * approved localhost assertion. Never reconnect mid-exchange. On timeout,
     * loss, cancellation or unrelated command, discard held state. */
    if (pin_held_fd>=0) {
        const bool same_connection=preflight &&
            ((pin_held_stage==1u && (pin_retries || pin_token_request || compat_token || compat_read || compat_info || generic_token || generic_info)) ||
             (pin_held_stage==2u && (verified_assertion || compat_assertion || compat_info ||
               ((generic_assertion || generic_registration) && web.pin_authorized) || generic_info ||
               (generic_next && next_assertions_pending>0u))) ||
             (pin_held_stage==3u && generic_next && next_assertions_pending>0u)) &&
            nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms());
        if (same_connection) {
            fd=pin_held_fd;
            reused_stage=pin_held_stage;
            pin_held_fd=-1;
            pin_held_stage=0u;
            nfc_pin_session_policy_clear(&pin_policy);
            reused_pin_fd=true;
            puts((pin_token_request || verified_assertion || compat_token || compat_assertion || generic_token || generic_assertion || generic_registration || generic_next) ?
                 "PIN_SESSION_REUSE: using same NFC connection for token/assertion." :
                 "PIN_PREFLIGHT_REUSE: using same NFC connection for read-only command.");
            fflush(stdout);
        } else {
            pin_held_close();
        }
    }
    if (!reused_pin_fd)
        fd=nfc_control_open(0u,NFC_BRIDGE_DISCOVER_TIMEOUT_MS,&cancel_requested);
    if (fd<0) {
        if (errno == ECANCELED || atomic_load(&cancel_requested))
            set_error(err,errcap,"NFC discovery cancelled");
        else if (errno == ETIMEDOUT)
            set_error(err,errcap,"NFC discovery timeout");
        else
            set_error(err,errcap,"NFC discovery or connection failed");
        goto out;
    }
    nfc_socket_t sock={.fd=fd,.cancel_flag=&cancel_requested};
    nfc_apdu_io_t io=nfc_socket_io(&sock);
    if (!reused_pin_fd) {
        result=nfc_apdu_select(&io,NFC_BRIDGE_SELECT_TIMEOUT_MS);
        if (result != NFC_APDU_OK) {
            set_error(err,errcap,nfc_apdu_status_string(result));
            goto out;
        }
    }
    const unsigned exchange_timeout = (general || localhost_browser_request || pin_readonly_request ||
                                       pin_token_request || verified_assertion || compat || generic_u2f)
        ? NFC_BRIDGE_REGISTRATION_TIMEOUT_MS
        : (request[0] == 0x0bu ? NFC_BRIDGE_SELECTION_TIMEOUT_MS
                               : NFC_BRIDGE_EXCHANGE_TIMEOUT_MS);
    result=generic_u2f ? nfc_apdu_u2f(&io,request,request_len,reply,reply_cap,reply_len,exchange_timeout)
                      : nfc_apdu_cbor(&io,request,request_len,reply,reply_cap,reply_len,exchange_timeout);
    if (result != NFC_APDU_OK) {
        set_error(err,errcap,nfc_apdu_status_string(result));
        goto out;
    }
    if (atomic_load(&cancel_requested)) {
        set_error(err,errcap,"NFC exchange cancelled");
        goto out;
    }
    // CTAP status byte 0x00 denotes success; error statuses are legitimate
    // authenticator responses, not NFC transport failures. Never log CBOR.
    ctap_status = *reply_len ? reply[0] : 0x100u;
    if (general && !generic_u2f) fprintf(stderr,"CTAP_STATUS: ctap=0x%02x status=0x%03x\n",
                         web.ctap_command,ctap_status);
    if (compat && !general) fprintf(stderr,"PIN_COMPAT_CTAP_STATUS: ctap=0x%02x status=0x%03x\n",
                        parsed.ctap_command,ctap_status);
    if (general && generic_assertion && ctap_status==0u) {
        next_assertions_pending=count_additional_assertions(reply,*reply_len);
        const bool up_uv=log_assertion_flags(reply,*reply_len);
        qualifies_for_early_cleanup=up_uv && !next_assertions_pending;
    }
    if (general && generic_next && ctap_status==0u) {
        if(next_assertions_pending>0u)next_assertions_pending--;
        if(next_assertions_pending==0u)qualifies_for_early_cleanup=log_assertion_flags(reply,*reply_len);
    }
    if (general && generic_registration && ctap_status==0u)
        qualifies_for_early_cleanup=true; // CTAP completion, not RP website verification
    if (generic_u2f && *reply_len>=2u && reply[*reply_len-2u]==0x90u && reply[*reply_len-1u]==0u)
        qualifies_for_early_cleanup=(request[1]!=3u); // U2F register/assertion, not VERSION
    ok = true;
    if (preflight && reused_pin_fd && (compat_read || compat_info || generic_info) &&
        *reply_len>0 && reply[0]==0 &&
        pin_arm()) {
        pin_held_fd=fd;pin_held_stage=reused_stage;keep_pin_fd=true;
        puts("PIN_COMPAT_READ_REUSE: retained activated NFC socket.");fflush(stdout);
    }
    if (preflight && pin_agreement && *reply_len>=2u && reply[0]==0x00u &&
        (reply[1]&0xe0u)==0xa0u &&
        pin_arm()) {
        /* Retain one activated NFC socket within the mode's bound. Legacy
         * read-only mode retains 12 s; opt-in PIN compatibility retains 45 s.
         * The socket cannot cross UHID cycles or survive an error/reset. */
        pin_held_fd=fd;
        pin_held_stage=1u;
        keep_pin_fd=true;
        puts(token_mode ? (compat ? "PIN_AGREEMENT_READY: NFC connection retained for next PIN step (45s)." :
                          "PIN_AGREEMENT_READY: NFC connection retained for next PIN step (12s).") :
             "PIN_PREFLIGHT_READY: one read-only follow-up permitted (12s).");
        fflush(stdout);
    }
    if (preflight && (pin_token_request || compat_token || generic_token) && reused_pin_fd && *reply_len>=2u &&
        reply[0]==0x00u && (reply[1]&0xe0u)==0xa0u &&
        pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=2u;
        keep_pin_fd=true;
        if(general) {
            token_scope_permissions=(web.pin_subcommand==9u)?web.permissions:3u;
            memset(token_scope_rp,0,sizeof token_scope_rp);
            if(web.pin_token_has_rp) memcpy(token_scope_rp,web.rp,strlen(web.rp)+1u);
        }
        puts(general ? "PIN_TOKEN_RELAYED: encrypted response forwarded; NFC connection retained (45s)." :
             compat ? "PIN_TOKEN_RELAYED_LOCALHOST: encrypted response forwarded; assertion window 45s." :
                      "PIN_TOKEN_RELAYED_LOCALHOST: encrypted response forwarded; NFC connection retained (12s).");
        fflush(stdout);
    }
    // Firefox may issue another getAssertion even after CTAP success. Preserve
    // the same activated NFC socket across bounded successful/error follow-ups;
    // PIN/UV authentication errors, cancellation and transport failures close it.
    // A successful CTAP response is not proof the browser/RP accepted it.
    // CTAP status is non-secret; do not log authenticatorData, signatures,
    // credential IDs, clientDataHash, or PIN auth bytes.
    if (general && preflight && reused_pin_fd && reused_stage==2u &&
        (generic_assertion || generic_registration) &&
        (ctap_status==0u || nfc_pin_assertion_retry_status(ctap_status)) && pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=2u;
        keep_pin_fd=true;
        puts("AUTH_SESSION_RETAINED: NFC connection retained for browser continuation (45s).");
        fflush(stdout);
    }
    // Retain a no-PIN getAssertion connection while the authenticator has
    // more credentials for this RP. For PIN sessions retain the same socket
    // through getNextAssertion and any subsequent browser assertion.
    if (general && preflight && generic_assertion && ctap_status==0u &&
        next_assertions_pending>0u && pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=(reused_stage==2u)?2u:3u;
        keep_pin_fd=true;
        puts("NEXT_ASSERTIONS_PENDING: NFC connection retained for additional assertions (45s).");
        fflush(stdout);
    }
    if (general && preflight && generic_next && ctap_status==0u &&
        next_assertions_pending>0u && pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=reused_stage;
        keep_pin_fd=true;
        puts("NEXT_ASSERTION_REUSE: NFC connection retained for additional assertions (45s).");
        fflush(stdout);
    }
    if (general && preflight && generic_next && ctap_status==0u &&
        next_assertions_pending==0u && reused_stage==2u && pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=2u;
        keep_pin_fd=true;
    }
    if (compat && preflight && reused_pin_fd && reused_stage==2u &&
        compat_assertion &&
        (ctap_status==0u || nfc_pin_assertion_retry_status(ctap_status)) &&
        pin_arm()) {
        pin_held_fd=fd;
        pin_held_stage=2u;
        keep_pin_fd=true;
        puts(ctap_status==0u ?
             "PIN_COMPAT_ASSERTION_SUCCESS_HELD: CTAP success; same NFC socket retained for browser continuation (45s)." :
             "PIN_COMPAT_ASSERTION_RETRY_HELD: CTAP error; same live NFC socket retained (45s).");
        fflush(stdout);
    }
    if (compat && reused_pin_fd && reused_stage==2u && compat_assertion && !keep_pin_fd) {
        puts("PIN_COMPAT_ASSERTION_SESSION_CLOSED: no bounded continuation available.");
        fflush(stdout);
    }
out:
    if (fd>=0 && !keep_pin_fd) (void)close(fd);
    /* Each stage is consumed once; no stale key agreement state remains. */
    if (!keep_pin_fd && pin_held_fd<0) {
        next_assertions_pending=0u;
        nfc_pin_session_policy_clear(&pin_policy);
        token_scope_permissions=0u;
        memset(token_scope_rp,0,sizeof token_scope_rp);
    }
    if (!ok) {
        if (reply && reply_cap) memset(reply,0,reply_cap);
        *reply_len=0u;
    }
    if (tracked_browser_auth)
        nfc_auth_lifecycle_finish(&browser_lifecycle,pin_clock_ms(),
                                  ok && qualifies_for_early_cleanup);
    atomic_store_explicit(&cancel_requested,false,memory_order_release);
    atomic_store_explicit(&active,false,memory_order_release);
    return ok;
}

void pcsc_fido_bridge_cancel(void) {
    atomic_store_explicit(&cancel_requested,true,memory_order_release);
}
void pcsc_fido_bridge_reset(void) {
    /* UHID close/stop/cancel destroys any unconsumed key-agreement state. */
    if (!atomic_load_explicit(&active,memory_order_acquire)) pin_held_close();
    // For this short-lived probe, reset aborts an active operation; when idle,
    // it clears a past cancellation. No background persistent device session.
    atomic_store_explicit(&cancel_requested,
        atomic_load_explicit(&active,memory_order_acquire),memory_order_release);
}
bool pcsc_fido_bridge_list_readers(FILE *out, char *err, size_t errcap) {
    (void)out;
    set_error(err,errcap,"Native NFC card monitor not implemented; no browser daemon");
    return false;
}
// Required by upstream logging interface; packet dumps are disabled.
bool pcsc_fido_bridge_debug_enabled(void) { return false; }
