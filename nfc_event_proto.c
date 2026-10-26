// SPDX-License-Identifier: MIT
#define _POSIX_C_SOURCE 200809L
#include "nfc_event_proto.h"
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <string.h>

static size_t align4(size_t v) { return (v+3u) & ~(size_t)3u; }

typedef struct { uint16_t type; const uint8_t *data; size_t len; } attr_t;
static bool next_attr(const uint8_t **p, size_t *rem, attr_t *a) {
    if (*rem < NLA_HDRLEN) return false;
    struct nlattr h;
    memcpy(&h, *p, NLA_HDRLEN);
    if (h.nla_len < NLA_HDRLEN || h.nla_len > *rem) return false;
    const size_t step = align4(h.nla_len);
    if (step > *rem) return false;
    a->type = h.nla_type & NLA_TYPE_MASK;
    a->data = *p + NLA_HDRLEN;
    a->len = h.nla_len - NLA_HDRLEN;
    *p += step;
    *rem -= step;
    return true;
}
static bool attr_u16(const attr_t *a, uint16_t *out) {
    if (a->len != sizeof(*out)) return false;
    memcpy(out,a->data,sizeof(*out));
    return true;
}
static bool attr_u32(const attr_t *a, uint32_t *out) {
    if (a->len != sizeof(*out)) return false;
    memcpy(out,a->data,sizeof(*out));
    return true;
}
static bool attr_is_string(const attr_t *a, const char *s) {
    const size_t n = strlen(s);
    return a->len == n+1u && memcmp(a->data,s,n+1u)==0;
}
static bool parse_group(const attr_t *group_attr, uint32_t *out) {
    const uint8_t *p=group_attr->data;
    size_t rem=group_attr->len;
    bool match=false, have_id=false;
    uint32_t id=0;
    while (rem) {
        attr_t a;
        if (!next_attr(&p,&rem,&a)) return false;
        if (a.type==CTRL_ATTR_MCAST_GRP_NAME) match=attr_is_string(&a,NFC_GENL_MCAST_EVENT_NAME);
        if (a.type==CTRL_ATTR_MCAST_GRP_ID) {
            if (!attr_u32(&a,&id)) return false;
            have_id=true;
        }
    }
    if (!match || !have_id || !id) return false;
    *out=id;
    return true;
}
static bool parse_family(const uint8_t *p,size_t rem,uint16_t *family,uint32_t *group) {
    bool found_family=false,found_group=false;
    uint16_t f=0;
    uint32_t g=0;
    while(rem) {
        attr_t a;
        if(!next_attr(&p,&rem,&a)) return false;
        if(a.type==CTRL_ATTR_FAMILY_ID) {
            if(!attr_u16(&a,&f)) return false;
            found_family=true;
        } else if(a.type==CTRL_ATTR_MCAST_GROUPS) {
            const uint8_t *nested=a.data;
            size_t left=a.len;
            while(left) {
                attr_t item;
                if(!next_attr(&nested,&left,&item)) return false;
                uint32_t candidate=0;
                if(parse_group(&item,&candidate)) {g=candidate; found_group=true;}
            }
        }
    }
    if (!found_family || !f || !found_group) return false;
    *family=f;*group=g;
    return true;
}
// Linux's TARGET_LOST event uses NFC_ATTR_DEVICE_NAME + TARGET_INDEX,
// whereas TARGETS_FOUND uses NFC_ATTR_DEVICE_INDEX. Accept both forms.
static bool device_name_index(const attr_t *a,uint32_t *result) {
    if(a->len<5u || a->len>16u || memcmp(a->data,"nfc",3)!=0 ||
       a->data[a->len-1u]!=0) return false;
    uint32_t number=0;
    for(size_t i=3;i<a->len-1u;i++) {
        const uint8_t c=a->data[i];
        if(c<'0' || c>'9' || number>(UINT32_MAX-(c-'0'))/10u) return false;
        number=number*10u+(c-'0');
    }
    *result=number;
    return true;
}
static bool parse_device(const uint8_t *p,size_t rem,uint32_t *device,
                         uint32_t *target,bool *has_target) {
    bool found_device=false;
    *has_target=false;
    while(rem) {
        attr_t a;
        if(!next_attr(&p,&rem,&a)) return false;
        if(a.type==NFC_ATTR_DEVICE_INDEX || a.type==NFC_ATTR_DEVICE_NAME) {
            uint32_t found=0;
            bool valid=a.type==NFC_ATTR_DEVICE_INDEX
                ? attr_u32(&a,&found) : device_name_index(&a,&found);
            if(!valid || (found_device && *device!=found)) return false;
            *device=found;
            found_device=true;
        } else if(a.type==NFC_ATTR_TARGET_INDEX) {
            if(!attr_u32(&a,target)) return false;
            *has_target=true;
        }
    }
    return found_device;
}
// GET_TARGET dump replies deliberately lack DEVICE_INDEX; the command was
// requested for exactly one device, so no device index is inferred here.
// Decode only target index/protocol mask. Never retain NFCID/card identifiers.
static bool parse_target_info(const uint8_t *p,size_t rem,uint32_t *target,
                              uint32_t *protocols) {
    bool have_target=false,have_protocols=false;
    while(rem) {
        attr_t a;
        if(!next_attr(&p,&rem,&a)) return false;
        if(a.type==NFC_ATTR_TARGET_INDEX) {
            if(!attr_u32(&a,target)) return false;
            have_target=true;
        } else if(a.type==NFC_ATTR_PROTOCOLS) {
            if(!attr_u32(&a,protocols)) return false;
            have_protocols=true;
        }
    }
    return have_target && have_protocols;
}
static bool push(nfc_notice_t *out,size_t cap,size_t *used,nfc_notice_t notice) {
    if(*used>=cap) return false;
    out[(*used)++]=notice;
    return true;
}
bool nfc_event_decode(const uint8_t *data,size_t len,uint16_t family,
                      nfc_notice_t *out,size_t cap,size_t *used) {
    if (!data || !out || !used) return false;
    *used=0;
    while(len) {
        if(len<NLMSG_HDRLEN) return false;
        struct nlmsghdr h;
        memcpy(&h,data,sizeof h);
        if(h.nlmsg_len<NLMSG_HDRLEN || h.nlmsg_len>len) return false;
        const size_t step=align4(h.nlmsg_len);
        // Some kernels omit final padding in a single-message datagram.
        if(step>len && h.nlmsg_len!=len) return false;
        const size_t wire_step=step>len ? len : step;
        const uint8_t *body=data+NLMSG_HDRLEN;
        size_t body_len=h.nlmsg_len-NLMSG_HDRLEN;
        nfc_notice_t notice={.seq=h.nlmsg_seq};
        bool recognized=false;
        if(h.nlmsg_type==NLMSG_ERROR) {
            // Linux permits truncated ACKs containing just the errno field.
            if(body_len < sizeof(int)) return false;
            int kernel_error=0;
            memcpy(&kernel_error,body,sizeof kernel_error);
            notice.type=NFC_NOTICE_ACK;
            notice.kernel_error=kernel_error<0 ? -kernel_error : kernel_error;
            recognized=true;
        } else if(h.nlmsg_type==NLMSG_DONE) {
            notice.type=NFC_NOTICE_DONE;
            recognized=true;
        } else if(body_len>=GENL_HDRLEN) {
            struct genlmsghdr gh;
            memcpy(&gh,body,sizeof gh);
            const uint8_t *attrs=body+GENL_HDRLEN;
            size_t alen=body_len-GENL_HDRLEN;
            if(h.nlmsg_type==GENL_ID_CTRL && gh.cmd==CTRL_CMD_NEWFAMILY) {
                if(!parse_family(attrs,alen,&notice.family,&notice.group)) return false;
                notice.type=NFC_NOTICE_FAMILY;
                recognized=true;
            } else if(family && h.nlmsg_type==family &&
                      gh.cmd==NFC_CMD_GET_TARGET && (h.nlmsg_flags & NLM_F_MULTI)) {
                if(!parse_target_info(attrs,alen,&notice.target,&notice.protocols)) return false;
                notice.type=NFC_NOTICE_TARGET_INFO;
                notice.has_target=true;
                recognized=true;
            } else if(family && h.nlmsg_type==family &&
                     (gh.cmd==NFC_EVENT_TARGETS_FOUND ||
                      gh.cmd==NFC_EVENT_TARGET_LOST ||
                      gh.cmd==NFC_EVENT_DEVICE_REMOVED)) {
                if(!parse_device(attrs,alen,&notice.device,&notice.target,
                                 &notice.has_target)) return false;
                notice.type=gh.cmd==NFC_EVENT_TARGETS_FOUND ? NFC_NOTICE_TARGETS_FOUND :
                            gh.cmd==NFC_EVENT_TARGET_LOST ? NFC_NOTICE_TARGET_LOST :
                            NFC_NOTICE_DEVICE_REMOVED;
                recognized=true;
            }
        }
        if(recognized && !push(out,cap,used,notice)) return false;
        data+=wire_step;
        len-=wire_step;
    }
    return true;
}
