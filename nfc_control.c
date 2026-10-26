// SPDX-License-Identifier: MIT
// Linux NFC generic-netlink controller discovery and open.
// Wire sequence modelled on libfido2 1.17.0 netlink.c and nfc_linux.c.
// DOES NOT link libfido2 internals, start a daemon, or create UHID devices.
#define _POSIX_C_SOURCE 200809L
#include "nfc_control.h"
#include <errno.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <poll.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MSG_CAP 1024u
#define NL_WAIT_SLICE_MS 25u
#define NFC_POLL_MAX_MS 120000u
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

static uint64_t clock_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static unsigned left_ms(uint64_t deadline) {
    uint64_t t = clock_ms();
    if (t >= deadline || t == UINT64_MAX) return 0;
    uint64_t d = deadline - t;
    return (unsigned)(d > UINT_MAX ? UINT_MAX : d);
}
static bool cancelled(const nfc_nl_io_t *io) {
    return io->cancelled && io->cancelled(io->ctx);
}
static size_t align4(size_t n) { return (n + 3u) & ~(size_t)3u; }

// Build one netlink message, without variable-sized allocations.
typedef struct {
    uint8_t data[MSG_CAP];
    size_t len;
} message_t;
static bool init_message(message_t *m, uint16_t type, uint16_t flags,
                         uint32_t sequence, uint8_t cmd, uint8_t version) {
    memset(m, 0, sizeof(*m));
    struct nlmsghdr nh = {.nlmsg_len=NLMSG_HDRLEN + GENL_HDRLEN,
        .nlmsg_type=type, .nlmsg_flags=NLM_F_REQUEST | flags,
        .nlmsg_seq=sequence, .nlmsg_pid=0};
    struct genlmsghdr gh = {.cmd=cmd, .version=version};
    memcpy(m->data, &nh, sizeof nh);
    memcpy(m->data + NLMSG_HDRLEN, &gh, sizeof gh);
    m->len = NLMSG_HDRLEN + GENL_HDRLEN;
    return true;
}
static bool add_attribute(message_t *m, uint16_t type, const void *bytes, size_t n) {
    if (n > UINT16_MAX - NLA_HDRLEN) return false;
    size_t actual = NLA_HDRLEN + n, aligned = align4(actual);
    if (aligned > sizeof(m->data) - m->len) return false;
    struct nlattr a = {.nla_len=(uint16_t)actual, .nla_type=type};
    memcpy(m->data + m->len, &a, NLA_HDRLEN);
    if (n) memcpy(m->data + m->len + NLA_HDRLEN, bytes, n);
    memset(m->data + m->len + actual, 0, aligned - actual);
    m->len += aligned;
    ((struct nlmsghdr *)(void *)m->data)->nlmsg_len = (uint32_t)m->len;
    return true;
}
static bool add_u32(message_t *m, uint16_t type, uint32_t v) {
    return add_attribute(m, type, &v, sizeof v);
}

typedef struct { uint16_t type; const uint8_t *data; size_t len; } attr_t;
// Returns one attribute, false at end or on invalid framing. Caller verifies
// that all bytes have been consumed when iteration finishes.
static bool next_attr(const uint8_t **p, size_t *rem, attr_t *out) {
    if (*rem < NLA_HDRLEN) return false;
    struct nlattr a;
    memcpy(&a, *p, NLA_HDRLEN);
    if (a.nla_len < NLA_HDRLEN || a.nla_len > *rem) return false;
    size_t step = align4(a.nla_len);
    if (step > *rem) return false;
    out->type = a.nla_type & NLA_TYPE_MASK;
    out->data = *p + NLA_HDRLEN;
    out->len = a.nla_len - NLA_HDRLEN;
    *p += step;
    *rem -= step;
    return true;
}
static bool attr_u16(const attr_t *a, uint16_t *v) {
    if (a->len != sizeof(*v)) return false;
    memcpy(v, a->data, sizeof *v); return true;
}
static bool attr_u32(const attr_t *a, uint32_t *v) {
    if (a->len != sizeof(*v)) return false;
    memcpy(v, a->data, sizeof *v); return true;
}
static bool attr_str(const attr_t *a, const char *s) {
    size_t n = strlen(s);
    return a->len == n + 1u && memcmp(a->data, s, n + 1u) == 0;
}
static bool parse_mcast_group(const attr_t *nested, uint32_t *id) {
    const uint8_t *p=nested->data; size_t n=nested->len;
    bool match=false, have_id=false; uint32_t group=0;
    attr_t a;
    while (next_attr(&p, &n, &a)) {
        if (a.type == CTRL_ATTR_MCAST_GRP_NAME) match=attr_str(&a, NFC_GENL_MCAST_EVENT_NAME);
        else if (a.type == CTRL_ATTR_MCAST_GRP_ID) have_id=attr_u32(&a, &group);
    }
    if (n || !match || !have_id || !group) return false;
    *id=group; return true;
}
static bool parse_family(const uint8_t *p, size_t n, uint16_t *family, uint32_t *group) {
    bool have_family=false, have_group=false;
    attr_t a;
    while (next_attr(&p, &n, &a)) {
        if (a.type == CTRL_ATTR_FAMILY_ID) have_family=attr_u16(&a, family);
        if (a.type == CTRL_ATTR_MCAST_GROUPS) {
            const uint8_t *q=a.data; size_t nq=a.len; attr_t g;
            while (next_attr(&q, &nq, &g)) {
                if (parse_mcast_group(&g, group)) have_group=true;
            }
            if (nq) return false;
        }
    }
    return n==0 && have_family && *family && have_group;
}
static bool parse_device_event(const uint8_t *p, size_t n, uint32_t device) {
    attr_t a;
    while (next_attr(&p, &n, &a)) {
        uint32_t got;
        if (a.type == NFC_ATTR_DEVICE_INDEX && attr_u32(&a, &got))
            return got==device;
    }
    return false;
}
static bool parse_target(const uint8_t *p, size_t n, uint32_t dev, uint32_t *target) {
    attr_t a; bool have_target=false;
    while (next_attr(&p, &n, &a)) {
        if (a.type == NFC_ATTR_DEVICE_INDEX) {
            uint32_t found;
            if (!attr_u32(&a, &found) || found != dev) return false;
        } else if (a.type == NFC_ATTR_TARGET_INDEX) {
            have_target=attr_u32(&a, target);
        }
    }
    return n==0 && have_target;
}

typedef enum { LOOKUP, POWER, POLL, EVENT, DUMP } phase_t;
typedef struct {
    phase_t phase;
    uint32_t seq, dev;
    uint16_t family;
    uint32_t group, target;
    bool seen_event, seen_target;
} proto_t;

static nfc_control_result_t process_packet(const uint8_t *buf, size_t len,
                             proto_t *p, bool *finished, int *kernel_errno) {
    *finished=false;
    // A single receive can contain several netlink messages.
    while (len >= NLMSG_HDRLEN) {
        struct nlmsghdr h;
        memcpy(&h, buf, sizeof h);
        if (h.nlmsg_len < NLMSG_HDRLEN || h.nlmsg_len > len) return NFC_CONTROL_PROTOCOL;
        const size_t span=align4(h.nlmsg_len);
        if (span > len) return NFC_CONTROL_PROTOCOL;
        const uint8_t *body=buf+NLMSG_HDRLEN;
        const size_t body_len=h.nlmsg_len-NLMSG_HDRLEN;
        if (h.nlmsg_type == NLMSG_ERROR && h.nlmsg_seq == p->seq) {
            if (body_len < sizeof(int)) return NFC_CONTROL_PROTOCOL;
            struct nlmsgerr err={0};
            memcpy(&err.error, body, sizeof err.error);
            if (err.error == 0 || (p->phase == POWER && err.error == -EALREADY)) {
                if (p->phase==POWER || p->phase==POLL) *finished=true;
            } else {
                *kernel_errno= err.error < 0 ? -err.error : err.error;
                return NFC_CONTROL_KERNEL_ERROR;
            }
        } else if (h.nlmsg_type == NLMSG_DONE && h.nlmsg_seq == p->seq) {
            if (p->phase==DUMP) *finished=true;
        } else if (body_len >= GENL_HDRLEN &&
            ((h.nlmsg_type == p->family && p->family) ||
             (h.nlmsg_type == GENL_ID_CTRL && p->phase == LOOKUP))) {
            struct genlmsghdr g; memcpy(&g, body, sizeof g);
            const uint8_t *attrs=body+GENL_HDRLEN;
            const size_t attrs_len=body_len-GENL_HDRLEN;
            if (p->family && h.nlmsg_type == p->family &&
                g.cmd == NFC_EVENT_TARGETS_FOUND) {
                if (parse_device_event(attrs, attrs_len, p->dev)) p->seen_event=true;
            } else if (h.nlmsg_seq == p->seq && p->phase == LOOKUP &&
                h.nlmsg_type == GENL_ID_CTRL && g.cmd == CTRL_CMD_NEWFAMILY) {
                if (!parse_family(attrs, attrs_len, &p->family, &p->group))
                    return NFC_CONTROL_PROTOCOL;
                *finished=true;
            } else if (h.nlmsg_seq == p->seq && p->phase == DUMP &&
                       h.nlmsg_type == p->family && g.cmd == NFC_CMD_GET_TARGET) {
                uint32_t target=0;
                if (parse_target(attrs, attrs_len, p->dev, &target)) {
                    p->target=target; p->seen_target=true;
                }
            }
        }
        buf+=span; len-=span;
    }
    if (len != 0) return NFC_CONTROL_PROTOCOL;
    return NFC_CONTROL_OK;
}
static nfc_control_result_t receive_phase(const nfc_nl_io_t *io, uint64_t deadline,
                                          proto_t *p, int *kernel_errno) {
    uint8_t buf[MSG_CAP];
    for (;;) {
        if (cancelled(io)) return NFC_CONTROL_CANCELLED;
        unsigned ms=left_ms(deadline);
        if (!ms) return NFC_CONTROL_TIMEOUT;
        if (ms > NL_WAIT_SLICE_MS) ms=NL_WAIT_SLICE_MS;
        ssize_t r=io->recv(io->ctx, buf, sizeof buf, ms);
        if (r == -EAGAIN || r == -EINTR || r == 0) continue;
        if (r < 0) return NFC_CONTROL_IO;
        if ((size_t)r > sizeof buf) return NFC_CONTROL_PROTOCOL;
        bool done=false;
        nfc_control_result_t s=process_packet(buf,(size_t)r,p,&done,kernel_errno);
        if (s!=NFC_CONTROL_OK) return s;
        if (done) return NFC_CONTROL_OK;
        if (p->phase==EVENT && p->seen_event) return NFC_CONTROL_OK;
    }
}
static nfc_control_result_t tx_phase(const nfc_nl_io_t *io, proto_t *p,
                        uint16_t type, uint16_t flags, uint8_t cmd) {
    message_t m;
    init_message(&m,type,flags,++p->seq,cmd,
                 p->phase==LOOKUP ? 1u : NFC_GENL_VERSION);
    if (p->phase == LOOKUP) {
        const uint16_t controller = GENL_ID_CTRL;
        if (!add_attribute(&m,CTRL_ATTR_FAMILY_ID,&controller,sizeof controller) ||
            !add_attribute(&m,CTRL_ATTR_FAMILY_NAME,NFC_GENL_NAME,strlen(NFC_GENL_NAME)+1))
            return NFC_CONTROL_ARGUMENT;
    } else if (!add_u32(&m,NFC_ATTR_DEVICE_INDEX,p->dev)) return NFC_CONTROL_ARGUMENT;
    if (p->phase == POLL && !add_u32(&m,NFC_ATTR_PROTOCOLS,NFC_PROTO_ISO14443_MASK))
        return NFC_CONTROL_ARGUMENT;
    ssize_t n=io->send(io->ctx,m.data,m.len);
    return n==(ssize_t)m.len ? NFC_CONTROL_OK : NFC_CONTROL_IO;
}

nfc_control_result_t nfc_control_find_target(const nfc_nl_io_t *io,
                   uint32_t device_index, unsigned timeout_ms, uint32_t *target_index) {
    if (!io || !io->send || !io->recv || !io->subscribe || !target_index ||
        timeout_ms==0 || timeout_ms > NFC_POLL_MAX_MS) return NFC_CONTROL_ARGUMENT;
    uint64_t now=clock_ms();
    if (now==UINT64_MAX) return NFC_CONTROL_IO;
    uint64_t deadline=now+timeout_ms;
    proto_t p={.phase=LOOKUP,.dev=device_index};
    int err=0;
    nfc_control_result_t s;
    if ((s=tx_phase(io,&p,GENL_ID_CTRL,0,CTRL_CMD_GETFAMILY))!=NFC_CONTROL_OK ||
        (s=receive_phase(io,deadline,&p,&err))!=NFC_CONTROL_OK) goto end;
    p.phase=POWER;
    if ((s=tx_phase(io,&p,p.family,NLM_F_ACK,NFC_CMD_DEV_UP))!=NFC_CONTROL_OK ||
        (s=receive_phase(io,deadline,&p,&err))!=NFC_CONTROL_OK) goto end;
    // Join BEFORE starting polling, to avoid missing a fast target event.
    if (io->subscribe(io->ctx,p.group)!=0) { s=NFC_CONTROL_IO; goto end; }
    p.phase=POLL;
    if ((s=tx_phase(io,&p,p.family,NLM_F_ACK,NFC_CMD_START_POLL))!=NFC_CONTROL_OK ||
        (s=receive_phase(io,deadline,&p,&err))!=NFC_CONTROL_OK) goto end;
    p.phase=EVENT;
    if (!p.seen_event && (s=receive_phase(io,deadline,&p,&err))!=NFC_CONTROL_OK) goto end;
    p.phase=DUMP;
    if ((s=tx_phase(io,&p,p.family,NLM_F_DUMP,NFC_CMD_GET_TARGET))!=NFC_CONTROL_OK ||
        (s=receive_phase(io,deadline,&p,&err))!=NFC_CONTROL_OK) goto end;
    if (!p.seen_target) s=NFC_CONTROL_PROTOCOL;
    else { *target_index=p.target; s=NFC_CONTROL_OK; }
end:
    if (s==NFC_CONTROL_KERNEL_ERROR && err>0) errno=err;
    return s;
}

// Kernel access is isolated here behind injectable transport operations.
typedef struct { int fd; const atomic_bool *cancel_flag; } kernel_io_t;
static bool kernel_cancel(void *arg) {
    kernel_io_t *k=arg;
    return k->cancel_flag && atomic_load(k->cancel_flag);
}
static ssize_t kernel_send(void *arg, const uint8_t *data, size_t n) {
    kernel_io_t *k=arg;
    struct sockaddr_nl sa={.nl_family=AF_NETLINK};
    ssize_t r=sendto(k->fd,data,n,MSG_DONTWAIT,(struct sockaddr *)&sa,sizeof sa);
    return r<0 ? -errno : r;
}
static ssize_t kernel_recv(void *arg, uint8_t *data, size_t cap, unsigned ms) {
    kernel_io_t *k=arg;
    struct pollfd pfd={.fd=k->fd,.events=POLLIN};
    int r=poll(&pfd,1,(int)ms);
    if (r==0 || (r<0 && errno==EINTR)) return -EAGAIN;
    if (r<0) return -errno;
    if (pfd.revents & (POLLERR|POLLHUP|POLLNVAL)) return -EIO;
    ssize_t n=recv(k->fd,data,cap,MSG_DONTWAIT|MSG_TRUNC);
    return n<0 ? -errno : n;
}
static int kernel_subscribe(void *arg, uint32_t group) {
    kernel_io_t *k=arg;
    return setsockopt(k->fd,SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,&group,sizeof group);
}
int nfc_control_connect_target(uint32_t dev, uint32_t target,
                                unsigned ms, const atomic_bool *cancelled_flag) {
    if (!ms) { errno=ETIMEDOUT; return -1; }
    uint64_t t=clock_ms();
    if (t==UINT64_MAX) { errno=EIO; return -1; }
    uint64_t deadline=t+ms;
    struct sockaddr_nfc sa={0};
    sa.sa_family=AF_NFC;
    sa.dev_idx=dev;
    sa.target_idx=target;
    sa.nfc_protocol=NFC_PROTO_ISO14443;
    int fd=socket(AF_NFC,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,NFC_SOCKPROTO_RAW);
    if (fd<0) return -1;
    if (connect(fd,(struct sockaddr *)&sa,sizeof sa)==0) return fd;
    if (errno!=EINPROGRESS && errno!=EALREADY && errno!=EAGAIN) {
        int e=errno; close(fd); errno=e; return -1;
    }
    for (;;) {
        if (cancelled_flag && atomic_load(cancelled_flag)) {
            close(fd); errno=ECANCELED; return -1;
        }
        unsigned left=left_ms(deadline);
        if (!left) { close(fd); errno=ETIMEDOUT; return -1; }
        if (left>NL_WAIT_SLICE_MS) left=NL_WAIT_SLICE_MS;
        struct pollfd pfd={.fd=fd,.events=POLLOUT};
        int r=poll(&pfd,1,(int)left);
        if (r<0 && errno==EINTR) continue;
        if (r<0) { int e=errno; close(fd); errno=e; return -1; }
        if (r==0) continue;
        int so_error=0; socklen_t elen=sizeof so_error;
        if (getsockopt(fd,SOL_SOCKET,SO_ERROR,&so_error,&elen)<0) {
            int e=errno; close(fd); errno=e; return -1;
        }
        if (so_error==0 && (pfd.revents&POLLOUT)) return fd;
        if (so_error==0) so_error=EIO;
        close(fd); errno=so_error; return -1;
    }
}
int nfc_control_open(uint32_t dev, unsigned ms, const atomic_bool *cancelled_flag) {
    if (!ms || ms>NFC_POLL_MAX_MS) { errno=EINVAL; return -1; }
    uint64_t start=clock_ms();
    if (start==UINT64_MAX) { errno=EIO; return -1; }
    uint64_t deadline=start+ms;
    int fd=socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_GENERIC);
    if (fd<0) return -1;
    struct sockaddr_nl addr={.nl_family=AF_NETLINK};
    if (bind(fd,(struct sockaddr *)&addr,sizeof addr)<0) {
        int e=errno; close(fd); errno=e; return -1;
    }
    kernel_io_t k={.fd=fd,.cancel_flag=cancelled_flag};
    const nfc_nl_io_t io={.ctx=&k,.send=kernel_send,.recv=kernel_recv,
                          .subscribe=kernel_subscribe,.cancelled=kernel_cancel};
    uint32_t target=0;
    nfc_control_result_t r=nfc_control_find_target(&io,dev,left_ms(deadline),&target);
    int e=errno;
    close(fd);
    if (r!=NFC_CONTROL_OK) {
        errno= r==NFC_CONTROL_TIMEOUT ? ETIMEDOUT :
               r==NFC_CONTROL_CANCELLED ? ECANCELED :
               r==NFC_CONTROL_KERNEL_ERROR ? e :
               r==NFC_CONTROL_ARGUMENT ? EINVAL :
               r==NFC_CONTROL_PROTOCOL ? EPROTO : EIO;
        return -1;
    }
    return nfc_control_connect_target(dev,target,left_ms(deadline),cancelled_flag);
}
const char *nfc_control_result_string(nfc_control_result_t s) {
    switch(s) {
      case NFC_CONTROL_OK: return "ok";
      case NFC_CONTROL_ARGUMENT: return "invalid argument";
      case NFC_CONTROL_TIMEOUT: return "timeout";
      case NFC_CONTROL_CANCELLED: return "cancelled";
      case NFC_CONTROL_PROTOCOL: return "invalid netlink reply";
      case NFC_CONTROL_IO: return "netlink I/O failure";
      case NFC_CONTROL_KERNEL_ERROR: return "kernel returned error";
      default: return "unknown";
    }
}
