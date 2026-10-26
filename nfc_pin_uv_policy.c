// SPDX-License-Identifier: MIT
#include "nfc_pin_uv_policy.h"
#include "nfc_localhost_policy.h"
#include "pcsc_fido/cbor_util.h"
#include <string.h>

#define MAX_REQ 1536u
static bool bstr(const uint8_t *r,size_t n,size_t *at,size_t want) {
    size_t k=0;
    if (!pcsc_fido_cbor_read_type_len(r,n,at,PCSC_FIDO_CBOR_MAJOR_BYTES,&k) ||
        k!=want || k>n-*at) return false;
    *at+=k;
    return true;
}
static bool uint_eq(const uint8_t *r,size_t n,size_t *at,size_t want) {
    /* This opt-in gate intentionally accepts only canonical single-byte
     * integers for the small CTAP values in its scope. */
    if (!r || !at || want>23u || *at>=n || r[*at]!=(uint8_t)want) return false;
    (*at)++;
    return true;
}
/* Key-agreement COSE_Key: EC2 / P-256 / ECDH-ES+HKDF-256, with no
 * unexpected optional parameters. Validate structure, not curve membership:
 * the authenticator performs actual cryptographic validation. */
static bool cose_ec2(const uint8_t *r,size_t n,size_t *at) {
    size_t pairs=0;
    if (!pcsc_fido_cbor_read_type_len(r,n,at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) || pairs!=5u)
        return false;
    unsigned seen=0;
    for (size_t i=0;i<pairs;i++) {
        size_t major_at=*at, key=0, bit=0;
        if (*at>=n) return false;
        if (r[*at]==1u || r[*at]==3u) {
            key=r[(*at)++];
            if (key==1u) {bit=1u; if(!uint_eq(r,n,at,2u)) return false;}
            else if (key==3u) {
                bit=2u;
                if (*at+2u>n || r[*at]!=0x38u || r[*at+1u]!=24u)
                    return false; // -25 ECDH-ES+HKDF-256
                *at+=2u;
            } else return false;
        } else {
            *at=major_at;
            if (*at>=n || r[*at]<0x20u || r[*at]>0x22u)
                return false;
            key=r[(*at)++]-0x20u;
            if (key==0u) {bit=4u; if(!uint_eq(r,n,at,1u)) return false;}
            else if (key==1u) {bit=8u; if(!bstr(r,n,at,32u)) return false;}
            else {bit=16u; if(!bstr(r,n,at,32u)) return false;}
        }
        if ((seen&bit)!=0) return false;
        seen|=bit;
    }
    return seen==31u;
}
bool nfc_pin_uv_localhost_token_allowed(const uint8_t *r,size_t n) {
    if(!r || n<20u || n>MAX_REQ || r[0]!=0x06u) return false;
    size_t at=1u,pairs=0,prev=0;
    unsigned seen=0;
    if(!pcsc_fido_cbor_read_type_len(r,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) || pairs!=6u)
        return false;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0;
        if (at>=n || r[at]<1u || r[at]>10u) return false;
        k=r[at++];
        if (k<=prev) return false;
        prev=k;
        switch(k) {
            case 1u: if(!uint_eq(r,n,&at,1u)) return false; seen|=1u;break;
            case 2u: if(!uint_eq(r,n,&at,9u)) return false; seen|=2u;break;
            case 3u: if(!cose_ec2(r,n,&at)) return false; seen|=4u;break;
            case 6u: if(!bstr(r,n,&at,16u)) return false; seen|=8u;break;
            case 9u: if(!uint_eq(r,n,&at,2u)) return false; seen|=16u;break;
            case 10u: {
                size_t length=0;
                if (!pcsc_fido_cbor_read_type_len(r,n,&at,PCSC_FIDO_CBOR_MAJOR_TEXT,&length) ||
                    length!=9u || length>n-at || memcmp(r+at,"localhost",9u)!=0) return false;
                at+=length; seen|=32u;break;
            }
            default:return false;
        }
    }
    return seen==63u && at==n;
}

bool nfc_pin_uv_localhost_assertion_allowed(const uint8_t *r,size_t n) {
    if(!r || n<8u || n>MAX_REQ || r[0]!=0x02u) return false;
    size_t at=1u,pairs=0;
    if(!pcsc_fido_cbor_read_type_len(r,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) ||
       pairs<5u || pairs>11u) return false;
    /* Strip only keys 6/7 from a copy, preserving the existing localhost
     * gate for every other field. Do not log or retain PIN auth bytes. */
    uint8_t copy[MAX_REQ];
    copy[0]=0x02u;
    copy[1]=0u;
    size_t out=2u,prev=0;
    bool auth=false,protocol=false;
    for(size_t i=0;i<pairs;i++) {
        const size_t begin=at;
        size_t k=0;
        if (at>=n || r[at]<1u || r[at]>11u) return false;
        k=r[at++];
        if (k<=prev)
            return false;
        prev=k;
        if (k==6u) {
            if(!bstr(r,n,&at,16u)) return false;
            auth=true;
        } else if (k==7u) {
            if(!uint_eq(r,n,&at,1u)) return false;
            protocol=true;
        } else {
            if(!pcsc_fido_cbor_skip_item(r,n,&at)) return false;
            if(at-begin>sizeof copy-out) return false;
            memcpy(copy+out,r+begin,at-begin);
            out+=at-begin;
        }
    }
    if (!auth || !protocol || at!=n || pairs<2u) return false;
    /* Canonical small map encoding, max 11 entries in the existing gate. */
    copy[1]=(uint8_t)(0xa0u+(pairs-2u));
    return nfc_localhost_webauthn_allowed(copy,out);
}
