// SPDX-License-Identifier: MIT
// Continuous mode keeps a single NFC poll pending while idle.
// Bounded waiting and held-key suppression share the NFC polling helper.
#define _POSIX_C_SOURCE 200809L
#include "nfc_auto_trigger.h"
#include "nfc_rearm_policy.h"
#include "nfc_event_proto.h"
#include "nfc_apdu.h"
#include "nfc_control.h"
#include "nfc_socket.h"
#include "pcsc_fido/daemon_signals.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define MSG_CAP 4096u
#define SLICE_MS 100
#define ACK_WAIT_MS 1500u
#define FAMILY_WAIT_MS 2000u
#define STOP_WAIT_MS 1200u
#define TARGET_DEVICE 0u
#define STEADY_IDLE_NOTICE_MS 30000u
#define GENERAL_IDLE_NOTICE_MS 1800000u
#define HELD_GUARD_MAX_MS 90000u
#define stop_requested pcsc_fido_daemon_stop_requested()

static uint64_t now_ms(void) {
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts)) return UINT64_MAX;
    return (uint64_t)ts.tv_sec*1000u+(uint64_t)ts.tv_nsec/1000000u;
}
static unsigned ms_left(uint64_t deadline) {
    const uint64_t n=now_ms();
    if(n==UINT64_MAX || n>=deadline) return 0;
    uint64_t left=deadline-n;
    return (unsigned)(left>UINT32_MAX ? UINT32_MAX:left);
}
static size_t align4(size_t n){ return (n+3u)&~(size_t)3u; }

typedef struct {
    int fd;
    uint16_t family;
    uint32_t group;
    uint32_t seq;
    uint64_t start;
    unsigned found, lost;
    bool removed;
} session_t;

static bool append_attr(uint8_t *out,size_t cap,size_t *len,uint16_t kind,
                        const void *value,size_t size) {
    if(size>UINT16_MAX-NLA_HDRLEN) return false;
    size_t bytes=NLA_HDRLEN+size;
    size_t padded=align4(bytes);
    if(*len>cap || padded>cap-*len) return false;
    struct nlattr a={.nla_len=(uint16_t)bytes,.nla_type=kind};
    memcpy(out+*len,&a,sizeof a);
    if(size) memcpy(out+*len+NLA_HDRLEN,value,size);
    if(padded>bytes) memset(out+*len+bytes,0,padded-bytes);
    *len+=padded;
    return true;
}
static bool send_cmd(session_t *s,uint16_t family,uint8_t version,uint8_t cmd,
                     uint16_t flags,uint32_t *sent_seq) {
    uint8_t buf[256]={0};
    size_t len=NLMSG_HDRLEN+GENL_HDRLEN;
    const uint32_t seq=++s->seq;
    struct genlmsghdr g={.cmd=cmd,.version=version};
    memcpy(buf+NLMSG_HDRLEN,&g,sizeof g);
    bool ok;
    if(family==GENL_ID_CTRL) {
        const char name[]=NFC_GENL_NAME;
        ok=append_attr(buf,sizeof buf,&len,CTRL_ATTR_FAMILY_NAME,name,sizeof name);
    } else {
        const uint32_t device=TARGET_DEVICE;
        ok=append_attr(buf,sizeof buf,&len,NFC_ATTR_DEVICE_INDEX,&device,sizeof device);
        if(ok && cmd==NFC_CMD_START_POLL) {
            const uint32_t proto=NFC_PROTO_ISO14443_MASK;
            ok=append_attr(buf,sizeof buf,&len,NFC_ATTR_PROTOCOLS,&proto,sizeof proto);
        }
    }
    if(!ok) return false;
    struct nlmsghdr h={.nlmsg_len=(uint32_t)len,.nlmsg_type=family,
        .nlmsg_flags=(uint16_t)(NLM_F_REQUEST|flags),.nlmsg_seq=seq,.nlmsg_pid=0};
    memcpy(buf,&h,sizeof h);
    struct sockaddr_nl kernel={.nl_family=AF_NETLINK};
    ssize_t sent=sendto(s->fd,buf,len,MSG_DONTWAIT,
                        (const struct sockaddr *)&kernel,sizeof kernel);
    if(sent!=(ssize_t)len) return false;
    *sent_seq=seq;
    return true;
}
static void display_event(session_t *s,const nfc_notice_t *notice) {
    if(notice->device!=TARGET_DEVICE) return;
    const char *name="DEVICE_REMOVED";
    if(notice->type==NFC_NOTICE_TARGETS_FOUND){name="TARGETS_FOUND"; ++s->found;}
    if(notice->type==NFC_NOTICE_TARGET_LOST){name="TARGET_LOST"; ++s->lost;}
    if(notice->type==NFC_NOTICE_DEVICE_REMOVED) s->removed=true;
    const uint64_t n=now_ms();
    const uint64_t dt=n>=s->start ? n-s->start : 0;
    printf("[+%llu.%03llu s] %s device=%u",(unsigned long long)(dt/1000u),
        (unsigned long long)(dt%1000u),name,(unsigned)notice->device);
    if(notice->has_target) printf(" target_index=%u",notice->target);
    puts("");
    fflush(stdout);
}
// Read and decode one datagram. Caller filters ACK/response by sequence.
//  1 = data returned; 0 = timeout/interrupted; -1 = I/O/protocol error.
static int read_notices(session_t *s,unsigned wait_ms,nfc_notice_t *notes,
                        size_t *count) {
    struct pollfd pfd={.fd=s->fd,.events=POLLIN};
    int r=poll(&pfd,1,(int)wait_ms);
    if(r==0 || (r<0 && errno==EINTR)) return 0;
    if(r<0) {perror("NFC_NETLINK_POLL_FAILED");return -1;}
    if(pfd.revents&(POLLERR|POLLHUP|POLLNVAL)) {
        fputs("NFC_NETLINK_SOCKET_ERROR: communication failure.\n",stderr);return -1;
    }
    uint8_t buf[MSG_CAP];
    ssize_t n=recv(s->fd,buf,sizeof buf,MSG_DONTWAIT|MSG_TRUNC);
    if(n<0 && (errno==EINTR || errno==EAGAIN)) return 0;
    if(n<0) {perror("NFC_NETLINK_RECV_FAILED");return -1;}
    if((size_t)n>sizeof buf || n==0) {
        fputs("NFC_EVENT_PACKET_INVALID: oversized or empty packet.\n",stderr);return -1;
    }
    if(!nfc_event_decode(buf,(size_t)n,s->family,notes,32u,count)) {
        fputs("NFC_EVENT_PACKET_INVALID: malformed generic-netlink packet.\n",stderr);return -1;
    }
    return 1;
}
// Returns 0 for success, positive kernel errno for negative ACK,
// -1 on time-out/transport error, -2 on user's interruption.
static int wait_response(session_t *s,uint32_t seq,bool looking_up,
                         unsigned max_ms,bool interruptible) {
    uint64_t start=now_ms();
    if(start==UINT64_MAX) return -1;
    const uint64_t deadline=start+max_ms;
    for(;;) {
        if(interruptible && stop_requested) return -2;
        unsigned left=ms_left(deadline);
        if(!left) return -1;
        if(left>SLICE_MS) left=SLICE_MS;
        nfc_notice_t notes[32];size_t count=0;
        int r=read_notices(s,left,notes,&count);
        if(r<0) return -1;
        if(!r) continue;
        for(size_t i=0;i<count;i++) {
            const nfc_notice_t *n=&notes[i];
            if(n->type==NFC_NOTICE_TARGETS_FOUND ||
               n->type==NFC_NOTICE_TARGET_LOST ||
               n->type==NFC_NOTICE_DEVICE_REMOVED) display_event(s,n);
            if(n->seq!=seq) continue;
            if(looking_up && n->type==NFC_NOTICE_FAMILY) {
                s->family=n->family;s->group=n->group;return 0;
            }
            if(n->type==NFC_NOTICE_ACK) return n->kernel_error;
        }
    }
}
static int request_ack(session_t *s,uint8_t cmd,unsigned ms,bool interruptible) {
    uint32_t seq=0;
    if(!send_cmd(s,s->family,NFC_GENL_VERSION,cmd,NLM_F_ACK,&seq)) {
        perror("NFC_COMMAND_SEND_FAILED");return -1;
    }
    return wait_response(s,seq,false,ms,interruptible);
}
// Dump the target list associated with this one successful START_POLL.
// The kernel dump entries lack a device index, because device 0 was specified
// in our GET_TARGET request; accept only ISO14443 and do not log NFCIDs.
static int find_iso14443_target(session_t *s,uint32_t *target) {
    uint32_t seq=0;
    if(!send_cmd(s,s->family,NFC_GENL_VERSION,NFC_CMD_GET_TARGET,NLM_F_DUMP,&seq)) {
        perror("NFC_GET_TARGET_SEND_FAILED"); return -1;
    }
    uint64_t begin=now_ms();
    if(begin==UINT64_MAX) return -1;
    const uint64_t deadline=begin+2500u;
    bool got_target=false;
    for(;;) {
        if(stop_requested) return -2;
        unsigned wait=ms_left(deadline);
        if(!wait) return -1;
        if(wait>SLICE_MS) wait=SLICE_MS;
        nfc_notice_t notes[32];size_t count=0;
        int rv=read_notices(s,wait,notes,&count);
        if(rv<0) return -1;
        if(!rv) continue;
        for(size_t i=0;i<count;i++) {
            nfc_notice_t *n=&notes[i];
            if(n->type==NFC_NOTICE_TARGETS_FOUND || n->type==NFC_NOTICE_TARGET_LOST ||
               n->type==NFC_NOTICE_DEVICE_REMOVED) display_event(s,n);
            if(n->seq!=seq) continue;
            if(n->type==NFC_NOTICE_TARGET_INFO &&
               (n->protocols & NFC_PROTO_ISO14443_MASK) && !got_target) {
                *target=n->target;got_target=true;
            } else if(n->type==NFC_NOTICE_ACK && n->kernel_error) {
                fprintf(stderr,"NFC_GET_TARGET_REJECTED: %s (code %d)\n",
                        strerror(n->kernel_error),n->kernel_error);
                return -1;
            } else if(n->type==NFC_NOTICE_DONE) {
                return got_target ? 0 : -1;
            }
        }
    }
}


static int await_found(session_t *s,uint64_t deadline,unsigned millis,
                       unsigned before) {
    uint64_t begin=now_ms();
    if(begin==UINT64_MAX) return -1;
    uint64_t end=begin+(uint64_t)millis;
    while(!stop_requested && s->found==before) {
        unsigned left=ms_left(deadline),remain=ms_left(end);
        if(left>remain) left=remain;
        if(!left) return 0;
        if(left>SLICE_MS) left=SLICE_MS;
        nfc_notice_t notes[32];size_t count=0;
        int got=read_notices(s,left,notes,&count);
        if(got<0) return -1;
        if(got) for(size_t i=0;i<count;i++)
            if(notes[i].type==NFC_NOTICE_TARGETS_FOUND ||
               notes[i].type==NFC_NOTICE_TARGET_LOST ||
               notes[i].type==NFC_NOTICE_DEVICE_REMOVED)
                display_event(s,&notes[i]);
    }
    if(s->removed) return -1;
    return stop_requested ? -1 : (s->found>before?1:0);
}

// One START_POLL remains active during arbitrarily long idle periods.
// Bounded 100-ms recv slices keep Ctrl+C responsive. The periodic notice
// reports that the event listener is still alive, NOT proof that the RF
// controller is transmitting. No STOP/START occurs at each notice.
// 1 = target event, -1 = socket/device error, -2 = stop requested.
static int await_found_steady(session_t *s,unsigned before) {
    uint64_t last_notice=now_ms();
    const uint64_t notice_interval=getenv("HP_NFC_IDLE_30M") ?
                                    GENERAL_IDLE_NOTICE_MS : STEADY_IDLE_NOTICE_MS;
    if(last_notice==UINT64_MAX) return -1;
    for(;;) {
        if(stop_requested) return -2;
        if(s->removed) return -1;
        if(s->found>before) return 1;
        nfc_notice_t notes[32];size_t count=0;
        int got=read_notices(s,SLICE_MS,notes,&count);
        if(got<0) return -1;
        if(got) for(size_t i=0;i<count;i++) {
            const nfc_notice_t *note=&notes[i];
            if(note->type==NFC_NOTICE_TARGETS_FOUND ||
               note->type==NFC_NOTICE_TARGET_LOST ||
               note->type==NFC_NOTICE_DEVICE_REMOVED) display_event(s,note);
        }
        if(s->removed) {
            fputs("NFC_DEVICE_REMOVED: idle discovery stopped; cannot assume polling is healthy.\n",stderr);
            return -1;
        }
        if(s->found>before) return 1;
        uint64_t now=now_ms();
        if(now==UINT64_MAX || now<last_notice) return -1;
        if(now-last_notice>=notice_interval) {
            puts("NFC_IDLE_WAITING: no target event; polling session remains open (RF state unverified).");
            fflush(stdout);
            last_notice=now;
        }
    }
}

// Only in guarded re-arm mode, while no virtual device exists, keep the
// activated card selected and check it periodically until communication fails.
// No CTAP, PIN, or credential APDUs are transmitted. I/O loss is *possible*
// removal, not proof; the next re-arm still requires a quiet interval.
// Returns 0 on possible loss, -1 on error/timeout, -2 on stop request.
static int await_held_loss(int fd, uint64_t deadline) {
    nfc_socket_t sock={.fd=fd,.cancel_flag=NULL};
    nfc_apdu_io_t io=nfc_socket_io(&sock);
    uint64_t began=now_ms();
    if(began==UINT64_MAX) return -1;
    for (;;) {
        if(stop_requested) return -2;
        uint64_t now=now_ms();
        if(now==UINT64_MAX || now>=deadline ||
           now-began>=NFC_REARM_HELD_MAX_MS) return -1;
        unsigned remaining=NFC_REARM_SELECT_PERIOD_MS;
        while(remaining>0) {
            if(stop_requested) return -2;
            unsigned chunk=remaining>SLICE_MS ? SLICE_MS:remaining;
            const struct timespec delay={.tv_sec=0,.tv_nsec=(long)chunk*1000000L};
            if(nanosleep(&delay,NULL)<0 && errno!=EINTR) return -1;
            remaining-=chunk;
        }
        if(stop_requested) return -2;
        if(now_ms()>=deadline) return -1;
        nfc_apdu_status_t selected=nfc_apdu_select(&io,2500u);
        if(selected!=NFC_APDU_OK) {
            puts("AUTO_HELD_COMMUNICATION_LOST: NFC communication lost; removal unconfirmed; checking quiet interval.");
            return 0;
        }
    }
}

static int auto_trigger_impl(unsigned detect_ms, bool guarded) {
    // detect_ms=0 is reserved for the foreground continuous-mode wait.
    // Bounded waits enforce their explicit deadlines.
    if(detect_ms!=0u && (detect_ms<1000u || detect_ms>120000u)) return -1;
    const bool steady_idle=detect_ms==0u;
    session_t s={.fd=-1};
    int active_fd=-1;
    bool poll_in_progress=false;
    int status=-1;
    s.fd=socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_GENERIC);
    if(s.fd<0) {perror("NFC_NETLINK_SOCKET_OPEN_FAILED"); goto out;}
    struct sockaddr_nl addr={.nl_family=AF_NETLINK};
    if(bind(s.fd,(const struct sockaddr *)&addr,sizeof addr)<0) {
        perror("NFC_NETLINK_BIND_FAILED"); goto out;
    }
    s.start=now_ms();
    if(s.start==UINT64_MAX) goto out;
    uint32_t seq=0;
    if(!send_cmd(&s,GENL_ID_CTRL,1u,CTRL_CMD_GETFAMILY,0,&seq)) goto out;
    int r=wait_response(&s,seq,true,FAMILY_WAIT_MS,true);
    if(r || !s.family || !s.group) {fputs("NFC_FAMILY_LOOKUP_FAILED: unable to resolve NFC family or event group.\n",stderr); goto out;}
    if(setsockopt(s.fd,SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,&s.group,sizeof s.group)<0) {
        perror("NFC_EVENT_SUBSCRIBE_FAILED"); goto out;
    }
    r=request_ack(&s,NFC_CMD_DEV_UP,ACK_WAIT_MS,true);
    if(r!=0 && r!=EALREADY) {fprintf(stderr,"NFC_DEV_UP_FAILED: code=%d\n",r); goto out;}
    uint64_t deadline=now_ms();
    if(deadline==UINT64_MAX) goto out;
    deadline=steady_idle ? UINT64_MAX : deadline+detect_ms;
    unsigned suppressed=0u;
    for(;;) {
        if(stop_requested) {status=-2; goto out;}
        if(!steady_idle && ms_left(deadline)==0u) {
            puts("NFC_DISCOVERY_TIMEOUT: no virtual device created.");
            status=0; goto out;
        }
        const unsigned before=s.found; // BEFORE ACK; early event can precede ACK.
        uint64_t start=now_ms();
        if(start==UINT64_MAX) goto out;
        r=request_ack(&s,NFC_CMD_START_POLL,ACK_WAIT_MS,true);
        if(r!=0) {
            // Positive values are the kernel errno from the netlink ACK;
            // negative values signify transport/timeout/interruption.
            // Never retry here: NCI/I2C may already be wedged.
            if(r>0)
                fprintf(stderr,"NFC START_POLL failed: kernel errno=%d (%s); no retry\n",
                        r,strerror(r));
            else
                fprintf(stderr,"NFC START_POLL failed: transport/timeout/interruption=%d; no retry\n",r);
            if(r==-2) status=-2;
            goto out;
        }
        poll_in_progress=true;
        if(guarded) {
            printf("NFC_START_POLL_OK: checking %u ms quiet interval; KEEP key away if removed.\n",
                   NFC_REARM_QUIET_MS);
        } else {
            puts("NFC_START_POLL_OK: waiting for NFC authenticator.");
        }
        if(steady_idle) puts("NFC_STEADY_IDLE_POLL: one START_POLL remains active while waiting; no periodic stop/restart.");
        fflush(stdout);
        bool quiet_ready=false;
        if(guarded) {
            // The target event may have been decoded during START_POLL ACK.
            // Measure the actual waited time: the global deadline might
            // pre-empt the quiet interval near the end of a bounded poll.
            uint64_t quiet_began=now_ms();
            if(quiet_began==UINT64_MAX) goto out;
            r=await_found(&s,deadline,NFC_REARM_QUIET_MS,before);
            if(r<0) {puts("NFC_DISCOVERY_INTERRUPTED_OR_FAILED");goto out;}
            uint64_t quiet_ended=now_ms();
            if(quiet_ended==UINT64_MAX || quiet_ended<quiet_began) goto out;
            if(r==0 && nfc_rearm_quiet_complete(
                  (unsigned)(quiet_ended-quiet_began),NFC_REARM_QUIET_MS,
                  s.found>before)) {
                puts("AUTO_REARM_READY: quiet interval observed; ready for next NFC authentication.");
                quiet_ready=true;
                fflush(stdout);
            }
            if(r==0 && !quiet_ready) {
                // End of discovery before quiet gate completed: fail closed.
                puts("AUTO_QUIET_INCOMPLETE: quiet interval not confirmed; virtual HID not created.");
                status=0;
                goto out;
            }
        } else {
            r=0;
        }
        if(r==0) {
            if(steady_idle) {
                r=await_found_steady(&s,before);
            } else {
                unsigned left=ms_left(deadline);
                if(left==0u) {puts("NFC_DISCOVERY_TIMEOUT: no virtual device created.");status=0;goto out;}
                r=await_found(&s,deadline,left,before);
            }
        }
        if(r==0) {puts("NFC_DISCOVERY_TIMEOUT: no virtual device created.");status=0;goto out;}
        if(r!=1) {
            puts("NFC_DISCOVERY_INTERRUPTED_OR_FAILED");
            if(r==-2) status=-2;
            goto out;
        }
        poll_in_progress=false; // Target discovery ends poll; STOP can return EINVAL.
        uint32_t target=0;
        if(find_iso14443_target(&s,&target)!=0) {
            puts("NFC_NON_ISO14443_OR_TARGET_ERROR: no virtual device created.");goto out;
        }
        active_fd=nfc_control_connect_target(TARGET_DEVICE,target,3500u,NULL);
        if(active_fd<0) {puts("NFC_TARGET_CONNECT_FAILED: no virtual device created.");goto out;}
        nfc_socket_t sock={.fd=active_fd,.cancel_flag=NULL};
        nfc_apdu_io_t io=nfc_socket_io(&sock);
        nfc_apdu_status_t selected=nfc_apdu_select(&io,3500u);
        if(selected!=NFC_APDU_OK) {
            puts("NFC_NOT_FIDO_SELECTED: no virtual device created.");goto out;
        }
        if(guarded && !quiet_ready) {
            puts("AUTO_HELD_SUPPRESSED: early rediscovery; virtual HID creation suppressed.");
            fflush(stdout);
            ++suppressed;
            if(suppressed>NFC_REARM_MAX_SUPPRESSIONS) {
                fputs("NFC_FAIL_CLOSED: excessive ambiguous rediscoveries.\n",stderr);
                goto out;
            }
            // Once a held card is suppressed, bound that communication probe
            // even though a subsequent idle wait may be open-ended.
            uint64_t held_deadline=deadline;
            if(steady_idle) {
                held_deadline=now_ms();
                if(held_deadline==UINT64_MAX) goto out;
                held_deadline+=HELD_GUARD_MAX_MS;
            }
            int lost=await_held_loss(active_fd,held_deadline);
            close(active_fd);
            active_fd=-1;
            if(lost!=0) {
                if(lost==-2) status=-2;
                else fputs("NFC_FAIL_CLOSED: held-key probe timed out or failed.\n",stderr);
                goto out;
            }
            puts("AUTO_GUARD_RETRY: waiting for a target-free interval.");
            fflush(stdout);
            continue;
        }
        puts("FIDO_SELECT_OK: compatible NFC authenticator detected.");
        status=1; goto out;
    }
out:
    if(active_fd>=0) close(active_fd);
    if(poll_in_progress && s.fd>=0) {
        int stopped=request_ack(&s,NFC_CMD_STOP_POLL,STOP_WAIT_MS,false);
        if(stopped==0) puts("NFC_STOP_POLL_OK");
        else if(stopped==EINVAL) puts("NFC_STOP_POLL_EINVAL: poll may already have ended.");
        else {
            fprintf(stderr,"NFC_STOP_POLL_NOT_CONFIRMED: code %d\n",stopped);
            status=-1;
        }
    }
    if(s.fd>=0) close(s.fd);
    puts("NFC_TRIGGER_SOCKET_CLOSED");
    fflush(stdout);
    if(pcsc_fido_daemon_stop_requested()) return -2;
    return status;
}
int nfc_auto_trigger_once(unsigned detect_ms) { return auto_trigger_impl(detect_ms,false); }
int nfc_auto_trigger_guarded(unsigned detect_ms) { return auto_trigger_impl(detect_ms,true); }
