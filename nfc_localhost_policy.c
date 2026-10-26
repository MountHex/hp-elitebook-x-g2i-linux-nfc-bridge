// SPDX-License-Identifier: MIT
// Small bounded CBOR *structural allowlist*, not a WebAuthn RP/origin verifier.
// Only the "localhost" RP is eligible for this compatibility allowlist.
// Explicit PIN/auth-token fields and management commands are excluded.
#include "nfc_localhost_policy.h"
#include "pcsc_fido/cbor_util.h"
#include <string.h>

#define MAX_BROWSER_REQUEST 1536u
#define MAX_MAP_ENTRIES 20u
#define MAX_PUBKEY_PARAMS 16u

static bool read_text(const uint8_t *p, size_t n, size_t *off, const char *expect) {
    size_t size = 0u;
    size_t e = strlen(expect);
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_TEXT,&size) ||
        size != e || size > n-*off || memcmp(p+*off,expect,e)!=0) return false;
    *off += size;
    return true;
}
static bool read_bytes_len(const uint8_t *p,size_t n,size_t *off,
                           size_t min,size_t max) {
    size_t size = 0u;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_BYTES,&size) ||
        size<min || size>max || size>n-*off) return false;
    *off += size;
    return true;
}
static bool is_text_key(const uint8_t *p,size_t n,size_t *off,const char *key,bool *match) {
    return pcsc_fido_cbor_read_text_key_matches(p,n,off,key,match);
}
// Browser makeCredential RP entity must contain id = "localhost".
static bool rp_entity(const uint8_t *p,size_t n,size_t *off) {
    size_t count=0u;
    bool id=false;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_MAP,&count) ||
        count==0 || count>MAX_MAP_ENTRIES) return false;
    for (size_t i=0;i<count;i++) {
        bool match=false;
        if (!is_text_key(p,n,off,"id",&match)) return false;
        if (match) {
            if (id || !read_text(p,n,off,"localhost")) return false;
            id=true;
        } else if (!pcsc_fido_cbor_skip_item(p,n,off)) return false;
    }
    return id;
}
// Require an actual (non-empty) user handle, not identity data from an account.
static bool user_entity(const uint8_t *p,size_t n,size_t *off) {
    size_t count=0u;
    bool id=false;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_MAP,&count) ||
        count==0 || count>MAX_MAP_ENTRIES) return false;
    for (size_t i=0;i<count;i++) {
        bool match=false;
        if (!is_text_key(p,n,off,"id",&match)) return false;
        if (match) {
            if (id || !read_bytes_len(p,n,off,1u,64u)) return false;
            id=true;
        } else if (!pcsc_fido_cbor_skip_item(p,n,off)) return false;
    }
    return id;
}
// Check ES256 is offered; allow other algorithms in the browser's list.
static bool pub_key_params(const uint8_t *p,size_t n,size_t *off) {
    size_t count=0u;
    bool es256=false;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_ARRAY,&count) ||
        count==0 || count>MAX_PUBKEY_PARAMS) return false;
    for (size_t i=0;i<count;i++) {
        size_t members=0u;
        bool type=false,alg=false,seen_type=false,seen_alg=false;
        if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_MAP,&members) ||
            members==0 || members>MAX_MAP_ENTRIES) return false;
        for (size_t k=0;k<members;k++) {
            size_t key_at=*off;
            bool match=false;
            if (!is_text_key(p,n,off,"type",&match)) return false;
            if (match) {
                if (seen_type || !read_text(p,n,off,"public-key")) return false;
                type=true; seen_type=true; continue;
            }
            *off=key_at;
            if (!is_text_key(p,n,off,"alg",&match)) return false;
            if (match) {
                size_t v=0u;
                if (seen_alg) return false;
                seen_alg=true;
                // ES256 COSE algorithm is integer -7 = CBOR nint argument 6.
                size_t arg_at=*off;
                if (pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_NINT,&v) && v==6u)
                    alg=true;
                else {
                    *off=arg_at;
                    if (!pcsc_fido_cbor_skip_item(p,n,off)) return false;
                }
            } else if (!pcsc_fido_cbor_skip_item(p,n,off)) return false;
        }
        if (!seen_type || !seen_alg) return false;
        if (type && alg) es256=true;
    }
    return es256;
}
// A browser can set "up" or "uv"; don't permit resident/discoverable keys.
static bool options_no_resident(const uint8_t *p,size_t n,size_t *off) {
    size_t count=0u;
    bool seen_rk=false;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_MAP,&count) ||
        count>MAX_MAP_ENTRIES) return false;
    for (size_t i=0;i<count;i++) {
        size_t at=*off;
        bool match=false, value=false;
        if (!is_text_key(p,n,off,"rk",&match)) return false;
        if (match) {
            if (seen_rk || !pcsc_fido_cbor_read_bool_value(p,n,off,&value) || value)
                return false;
            seen_rk=true;
        } else {
            *off=at;
            if (!is_text_key(p,n,off,"up",&match)) return false;
            if (match) {
                if (!pcsc_fido_cbor_read_bool_value(p,n,off,&value)) return false;
            } else {
                *off=at;
                if (!is_text_key(p,n,off,"uv",&match)) return false;
                if (match) {
                    if (!pcsc_fido_cbor_read_bool_value(p,n,off,&value)) return false;
                } else return false;
            }
        }
    }
    return true;
}
static bool allow_credentials(const uint8_t *p,size_t n,size_t *off) {
    size_t count=0u;
    if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_ARRAY,&count) ||
        count==0 || count>16u) return false;
    for (size_t i=0;i<count;i++) {
        size_t members=0u;
        bool seen_id=false, seen_type=false;
        if (!pcsc_fido_cbor_read_type_len(p,n,off,PCSC_FIDO_CBOR_MAJOR_MAP,&members) ||
            members==0 || members>MAX_MAP_ENTRIES) return false;
        for (size_t j=0;j<members;j++) {
            size_t at=*off;
            bool match=false;
            if (!is_text_key(p,n,off,"id",&match)) return false;
            if (match) {
                if (seen_id || !read_bytes_len(p,n,off,1u,1023u)) return false;
                seen_id=true;
            } else {
                *off=at;
                if (!is_text_key(p,n,off,"type",&match)) return false;
                if (match) {
                    if (seen_type || !read_text(p,n,off,"public-key")) return false;
                    seen_type=true;
                } else if (!pcsc_fido_cbor_skip_item(p,n,off)) return false;
            }
        }
        if (!seen_id || !seen_type) return false;
    }
    return true;
}

bool nfc_localhost_webauthn_allowed(const uint8_t *req,size_t len) {
    if (!req || len<5u || len>MAX_BROWSER_REQUEST ||
        (req[0]!=0x01u && req[0]!=0x02u)) return false;
    const bool registration=req[0]==0x01u;
    size_t off=1u, count=0u;
    unsigned seen=0u;
    if (!pcsc_fido_cbor_read_type_len(req,len,&off,PCSC_FIDO_CBOR_MAJOR_MAP,&count) ||
        count<2u || count>11u) return false;
    for (size_t i=0;i<count;i++) {
        size_t key=0u;
        if (!pcsc_fido_cbor_read_uint_value(req,len,&off,&key) || key<1u || key>11u ||
            (seen & (1u<<key))) return false;
        seen |= 1u<<key;
        switch (key) {
            case 1u:
                if (registration) {
                    if (!read_bytes_len(req,len,&off,32u,32u)) return false;
                } else if (!read_text(req,len,&off,"localhost")) return false;
                break;
            case 2u:
                if (registration) {
                    if (!rp_entity(req,len,&off)) return false;
                } else if (!read_bytes_len(req,len,&off,32u,32u)) return false;
                break;
            case 3u:
                if (registration) {
                    if (!user_entity(req,len,&off)) return false;
                } else if (!allow_credentials(req,len,&off)) return false;
                break;
            case 4u:
                if (registration) {
                    if (!pub_key_params(req,len,&off)) return false;
                } else if (!pcsc_fido_cbor_skip_item(req,len,&off)) return false;
                break;
            case 5u:
                if (registration) {
                    // Optional excludeList must be structurally bounded.
                    if (!pcsc_fido_cbor_skip_item(req,len,&off)) return false;
                } else if (!options_no_resident(req,len,&off)) return false;
                break;
            case 6u:
                // makeCredential extensions allowed; assert PIN auth key 6 forbidden.
                if (!registration || !pcsc_fido_cbor_skip_item(req,len,&off)) return false;
                break;
            case 7u:
                // Registration options: prohibit resident key; assertion key 7 is PIN protocol.
                if (!registration || !options_no_resident(req,len,&off)) return false;
                break;
            // makeCredential keys 8/9 = PIN/UV auth; assert keys 6/7 = PIN/UV auth.
            // makeCredential key 10 = enterprise attestation. Always reject.
            default: return false;
        }
    }
    const unsigned required=registration ? ((1u<<1)|(1u<<2)|(1u<<3)|(1u<<4))
                                         : ((1u<<1)|(1u<<2)|(1u<<3));
    return (seen & required)==required && off==len;
}
