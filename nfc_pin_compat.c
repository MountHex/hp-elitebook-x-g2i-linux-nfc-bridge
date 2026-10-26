// SPDX-License-Identifier: MIT
#include "nfc_pin_compat.h"
#include "pcsc_fido/cbor_util.h"
#include <string.h>
#define MAX_REQUEST 1536u
#define MAX_PAIRS 24u
static bool uint_val(const uint8_t *p,size_t n,size_t *at,size_t *value) {
    return pcsc_fido_cbor_read_uint_value(p,n,at,value);
}
static bool bytes_len(const uint8_t *p,size_t n,size_t *at,size_t low,size_t high) {
    size_t len=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_BYTES,&len) ||
       len<low || len>high || len>n-*at) return false;
    *at+=len;return true;
}
static bool text_equals(const uint8_t *p,size_t n,size_t *at,const char *s) {
    size_t len=0,expected=strlen(s);
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_TEXT,&len) ||
       len!=expected || len>n-*at || memcmp(p+*at,s,len)!=0) return false;
    *at+=len;return true;
}
static bool pin_map(const uint8_t *p,size_t n,nfc_compat_result_t *out,const char *rp) {
    size_t at=1,pairs=0;
    bool seen[11]={false};
    bool keyagreement=false,pinhash=false,perm=false,permrp=false,read_sub=false;
    unsigned protocol=0,sub=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) ||
       pairs<1 || pairs>10) return false;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0,val=0;
        if(!uint_val(p,n,&at,&k) || k<1 || k>10 || seen[k]) return false;
        seen[k]=true;
        switch(k) {
        case 1:
            if(!uint_val(p,n,&at,&val) || (val!=1 && val!=2)) return false;
            protocol=(unsigned)val;out->pin_protocol=protocol;break;
        case 2:
            if(!uint_val(p,n,&at,&val) || val>255) return false;
            sub=(unsigned)val;out->pin_subcommand=sub;read_sub=true;break;
        case 3:
            /* COSE EC2 key is structurally bounded; authenticator checks curve. */
            if(at>=n || (p[at]>>5)!=5 || !pcsc_fido_cbor_skip_item(p,n,&at)) return false;
            keyagreement=true;break;
        case 6:
            /* Protocol 2 may encrypt with random IV prepended. */
            if(!bytes_len(p,n,&at,16,64)) return false;
            pinhash=true;break;
        case 9:
            if(!uint_val(p,n,&at,&val) || val!=2u) return false;
            perm=true;break;
        case 10:
            if(!text_equals(p,n,&at,rp)) return false;
            permrp=true;break;
        default:
            /* Do not permit setPIN/changePIN fields even with another subcommand. */
            return false;
        }
    }
    if(at!=n || !read_sub) return false;
    out->pin_subcommand=sub;out->pin_protocol=protocol;
    if(sub==1 || sub==2 || sub==7) {
        if(keyagreement || pinhash || perm || permrp) return false;
        out->op=(sub==2)?NFC_COMPAT_PIN_AGREEMENT:NFC_COMPAT_PIN_READ;
        return true;
    }
    if(sub==5 || sub==9) {
        if(!protocol || !keyagreement || !pinhash) return false;
        if(sub==9 && (!perm || !permrp)) return false;
        if(sub==5 && (perm || permrp)) return false;
        out->op=NFC_COMPAT_PIN_TOKEN;return true;
    }
    return false;
}
static bool assertion_map(const uint8_t *p,size_t n,const char *rp,bool *pin_auth) {
    size_t at=1,pairs=0;
    bool seen[8]={false};
    unsigned required=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs) ||
       pairs<2 || pairs>7) return false;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0,val=0;
        if(!uint_val(p,n,&at,&k) || k<1 || k>7 || seen[k]) return false;
        seen[k]=true;
        if(k==1) {
            if(!text_equals(p,n,&at,rp)) return false;
            required|=1u;
        } else if(k==2) {
            if(!bytes_len(p,n,&at,32,32)) return false;
            required|=2u;
        } else if(k==6) {
            if(!bytes_len(p,n,&at,16,32)) return false;
        } else if(k==7) {
            if(!uint_val(p,n,&at,&val) || (val!=1 && val!=2)) return false;
        } else {
            if(!pcsc_fido_cbor_skip_item(p,n,&at)) return false;
        }
    }
    if(pin_auth) *pin_auth=seen[6] && seen[7];
    return at==n && required==3u && seen[6]==seen[7];
}
nfc_compat_result_t nfc_pin_compat_classify(const uint8_t *p,size_t n,const char *rp) {
    nfc_compat_result_t out={0};
    if(!p || !rp || !*rp || n<1 || n>MAX_REQUEST) return out;
    out.ctap_command=p[0];
    if(n==1 && p[0]==0x04) out.op=NFC_COMPAT_INFO;
    else if(n==1 && p[0]==0x08) out.op=NFC_COMPAT_NEXT_ASSERTION;
    else if(p[0]==0x06) (void)pin_map(p,n,&out,rp);
    else if(p[0]==0x02 && assertion_map(p,n,rp,&out.pin_authorized_assertion)) out.op=NFC_COMPAT_ASSERTION;
    return out;
}
