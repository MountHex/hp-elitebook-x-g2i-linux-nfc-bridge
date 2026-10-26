// SPDX-License-Identifier: MIT
// Structurally bounded CTAP2 authentication and both resident/non-resident
// registration requests for general relying parties. The authenticator
// validates protocol semantics, PIN tokens and signatures. Firefox provides
// WebAuthn origin validation; this is NOT an origin verifier.
#include "nfc_general_webauthn.h"
#include "pcsc_fido/cbor_util.h"
#include <string.h>
#define MAX_REQUEST 1536u
#define MAX_PAIRS 24u
static bool read_uint(const uint8_t *p,size_t n,size_t *at,size_t *v) {
    return pcsc_fido_cbor_read_uint_value(p,n,at,v);
}
static bool read_bytes(const uint8_t *p,size_t n,size_t *at,size_t min,size_t max) {
    size_t l=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_BYTES,&l)||l<min||l>max||l>n-*at) return false;
    *at+=l;return true;
}
static bool text_key(const uint8_t *p,size_t n,size_t *at,const char *key,bool *match) {
    return pcsc_fido_cbor_read_text_key_matches(p,n,at,key,match);
}
static bool rp_text(const uint8_t *p,size_t n,size_t *at,char *out) {
    size_t l=0;
    if (!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_TEXT,&l)||
        !l || l>=NFC_GENERAL_RP_CAP || l>n-*at) return false;
    // Most browser RPs use DNS ASCII, IDNA A-labels, IPv4 or localhost.
    // This validation is only a control-character/NUL guard, not an origin policy.
    for(size_t i=0;i<l;i++) if(p[*at+i]<0x21u||p[*at+i]>0x7eu) return false;
    memcpy(out,p+*at,l);out[l]='\0';*at+=l;return true;
}
static bool rp_entity(const uint8_t *p,size_t n,size_t *at,char *out) {
    size_t pairs=0;bool id=false;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||!pairs||pairs>MAX_PAIRS) return false;
    for(size_t i=0;i<pairs;i++) {
        bool match=false;
        if(!text_key(p,n,at,"id",&match)) return false;
        if(match) {if(id||!rp_text(p,n,at,out)) return false;id=true;}
        else if(!pcsc_fido_cbor_skip_item(p,n,at)) return false;
    }
    return id;
}
static bool user_entity(const uint8_t *p,size_t n,size_t *at) {
    size_t pairs=0;bool id=false;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||!pairs||pairs>MAX_PAIRS) return false;
    for(size_t i=0;i<pairs;i++) {
        bool match=false;
        if(!text_key(p,n,at,"id",&match)) return false;
        if(match) {if(id||!read_bytes(p,n,at,1,64)) return false;id=true;}
        else if(!pcsc_fido_cbor_skip_item(p,n,at)) return false;
    }
    return id;
}
static bool params_array(const uint8_t *p,size_t n,size_t *at) {
    size_t count=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_ARRAY,&count)||!count||count>32) return false;
    for(size_t i=0;i<count;i++) if(!pcsc_fido_cbor_skip_item(p,n,at)) return false;
    return true;
}
// Pass ordinary authenticatorMakeCredential options, including rk=true,
// through unchanged. The YubiKey decides whether resident credentials are
// available and permitted; do not turn the feature off in our bridge.
static bool registration_options(const uint8_t *p,size_t n,size_t *at) {
    size_t pairs=0;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||pairs>MAX_PAIRS) return false;
    for(size_t i=0;i<pairs;i++) {
        size_t keylen=0;
        if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_TEXT,&keylen) ||
           !keylen || keylen>64u || keylen>n-*at) return false;
        *at+=keylen;
        bool value=false;
        if(!pcsc_fido_cbor_read_bool_value(p,n,at,&value)) return false;
        (void)value;
    }
    return true;
}
static bool credential(const uint8_t *p,size_t n,size_t *at,nfc_general_request_t *out,bool registration) {
    size_t pairs=0,seen=0;
    const size_t max_key=registration?10u:7u;
    if(!pcsc_fido_cbor_read_type_len(p,n,at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||
       pairs<2u||pairs>max_key) return false;
    bool have_auth=false,have_protocol=false;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0,v=0;
        if(!read_uint(p,n,at,&k)||!k||k>max_key||(seen&(1u<<k))) return false;
        seen|=(1u<<k);
        if(registration) {
            switch(k) {
            case 1: if(!read_bytes(p,n,at,32,32)) return false;break;
            case 2: if(!rp_entity(p,n,at,out->rp)) return false;break;
            case 3: if(!user_entity(p,n,at)) return false;break;
            case 4: if(!params_array(p,n,at)) return false;break;
            case 7: if(!registration_options(p,n,at)) return false;break;
            case 8: if(!read_bytes(p,n,at,16,32)) return false;have_auth=true;break;
            case 9: if(!read_uint(p,n,at,&v)||(v!=1&&v!=2))return false;have_protocol=true;break;
            case 10: if(!read_uint(p,n,at,&v)||v<1u||v>2u)return false;break;
            default: if(!pcsc_fido_cbor_skip_item(p,n,at))return false;break;
            }
        } else {
            switch(k) {
            case 1: if(!rp_text(p,n,at,out->rp))return false;break;
            case 2: if(!read_bytes(p,n,at,32,32))return false;break;
            case 6: if(!read_bytes(p,n,at,16,32))return false;have_auth=true;break;
            case 7: if(!read_uint(p,n,at,&v)||(v!=1&&v!=2))return false;have_protocol=true;break;
            default: if(!pcsc_fido_cbor_skip_item(p,n,at))return false;break;
            }
        }
    }
    if(*at!=n || have_auth!=have_protocol) return false;
    if(registration) {
        if((seen&(1u<<1 | 1u<<2 | 1u<<3 | 1u<<4))!=(1u<<1 | 1u<<2 | 1u<<3 | 1u<<4))return false;
    } else if((seen&((1u<<1)|(1u<<2)))!=((1u<<1)|(1u<<2)))return false;
    out->pin_authorized=have_auth;
    return true;
}
static bool pin_request(const uint8_t *p,size_t n,nfc_general_request_t *out) {
    size_t at=1,pairs=0,seen=0;
    bool agreement=false,hash=false,perms=false,has_rp=false;
    if(!pcsc_fido_cbor_read_type_len(p,n,&at,PCSC_FIDO_CBOR_MAJOR_MAP,&pairs)||!pairs||pairs>10)return false;
    for(size_t i=0;i<pairs;i++) {
        size_t k=0,v=0;
        if(!read_uint(p,n,&at,&k)||k<1||k>10||(seen&(1u<<k)))return false;
        seen|=(1u<<k);
        switch(k) {
        case 1: if(!read_uint(p,n,&at,&v)||(v!=1&&v!=2))return false;out->pin_protocol=(unsigned)v;break;
        case 2: if(!read_uint(p,n,&at,&v)||v>255)return false;out->pin_subcommand=(unsigned)v;break;
        case 3: if(at==n||(p[at]>>5)!=PCSC_FIDO_CBOR_MAJOR_MAP||!pcsc_fido_cbor_skip_item(p,n,&at))return false;agreement=true;break;
        case 6: if(!read_bytes(p,n,&at,16,64))return false;hash=true;break;
        case 9: if(!read_uint(p,n,&at,&v)||v<1||v>3)return false;out->permissions=(unsigned)v;perms=true;break;
        case 10: if(!rp_text(p,n,&at,out->rp))return false;has_rp=true;break;
        default: return false; /* subcommands 3/4 set/change PIN, etc. */
        }
    }
    if(at!=n||!(seen&(1u<<2)))return false;
    unsigned sub=out->pin_subcommand;
    if(sub==1||sub==2||sub==7) {
        if(agreement||hash||perms||has_rp)return false;
        out->op=sub==2?NFC_GENERAL_PIN_AGREEMENT:NFC_GENERAL_PIN_READ;
        return true;
    }
    if(sub==5||sub==9) {
        if(!out->pin_protocol||!agreement||!hash)return false;
        if(sub==5 && (perms||has_rp))return false;
        if(sub==9 && (!perms || !has_rp))return false;
        out->pin_token_has_rp=has_rp;
        out->op=NFC_GENERAL_PIN_TOKEN;
        return true;
    }
    return false;
}
nfc_general_request_t nfc_general_classify(const uint8_t *p,size_t n) {
    nfc_general_request_t out={0};
    if(!p||n<1||n>MAX_REQUEST)return out;
    out.ctap_command=p[0];
    if(n==1&&p[0]==4)out.op=NFC_GENERAL_INFO;
    else if(p[0]==6) {if(!pin_request(p,n,&out))out.op=NFC_GENERAL_REJECT;}
    else if(p[0]==8 && n==1)out.op=NFC_GENERAL_NEXT_ASSERTION;
    else if(p[0]==2) {size_t at=1;if(credential(p,n,&at,&out,false))out.op=NFC_GENERAL_ASSERTION;}
    else if(p[0]==1) {size_t at=1;if(credential(p,n,&at,&out,true))out.op=NFC_GENERAL_REGISTRATION;}
    return out;
}
