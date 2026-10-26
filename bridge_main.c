// SPDX-License-Identifier: MIT
// Browser FIDO2/WebAuthn/U2F NFC-to-UHID bridge.
#define _POSIX_C_SOURCE 200809L
#include "pcsc_fido/daemon_signals.h"
#include "nfc_browser_gate.h"
#include "nfc_runtime_mode.h"
#include "bridge_identity.h"
#include "nfc_auto_trigger.h"
#include "nfc_recovery_policy.h"
#include "nfc_auto_window.h"
#include "nfc_auto_bridge_event.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/request_assembly.h"
#include "pcsc_fido/uhid_transport.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/major.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define START_MS 6000
#define GENERAL_ACTIVE_MS 60000u
#define GENERAL_COMPLETION_GRACE_MS 10000u

static int64_t time_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Requirement: only CAP_NET_ADMIN, never UID 0 or broad capabilities. */
static bool only_net_admin_effective(void) {
  FILE *f = fopen("/proc/self/status", "r");
  if (!f) return false;
  char line[256];
  bool seen = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "CapEff:", 7) != 0) continue;
    unsigned long long value = 0;
    if (sscanf(line + 7, "%llx", &value) == 1 && value == (1ULL << 12)) seen = true;
    break;
  }
  fclose(f);
  return seen;
}

static bool preopened_uhid_fd(int fd) {
  struct stat st;
  int flags = fcntl(fd, F_GETFL);
  return fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) &&
         major(st.st_rdev) == 10 && minor(st.st_rdev) == 239 &&
         flags >= 0 && (flags & O_ACCMODE) == O_RDWR;
}

/* Open validated UHID FD3 via dedicated non-root group when it is not supplied. */
static bool obtain_group_uhid_fd3(bool group_mode) {
  if (preopened_uhid_fd(3)) return true;
  if (!group_mode) return false;
  errno = 0;
  if (fcntl(3, F_GETFD) >= 0 || errno != EBADF) return false;
  int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
  if (fd < 0) return false;
  if (fd != 3) {
    if (dup2(fd, 3) < 0) { close(fd); return false; }
    close(fd);
  }
  if (!preopened_uhid_fd(3)) { close(3); return false; }
  puts("UHID_OPENED_NONROOT: group-authorized /dev/uhid opened as FD3.");
  return true;
}

/* Observe sysfs but never open /dev/hidraw or change device permissions. */
static bool virtual_hidraw(char *buf, size_t cap) {
  DIR *d = opendir("/sys/class/hidraw");
  if (!d) return false;
  bool found = false;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strncmp(ent->d_name, "hidraw", 6) != 0) continue;
    char path[256];
    if (snprintf(path, sizeof(path), "/sys/class/hidraw/%s/device/uevent",
                 ent->d_name) >= (int)sizeof(path)) continue;
    FILE *f = fopen(path, "r");
    if (!f) continue;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
      static const char expected[] = "HID_NAME=" NFC_BRIDGE_UHID_NAME;
      if (strncmp(line, expected, sizeof(expected)-1) == 0 &&
          (line[sizeof(expected)-1] == '\n' ||
           line[sizeof(expected)-1] == '\0') &&
          strlen(ent->d_name) < cap) {
        strcpy(buf, ent->d_name);
        found = true;
        break;
      }
    }
    fclose(f);
    if (found) break;
  }
  closedir(d);
  return found;
}

/* After UHID_DESTROY, wait for sysfs to stop advertising the old key.
 * Do not start the next discovery if the prior virtual device still exists.
 * Unlike DESTROY's write result, this is observable kernel state, although
 * disappearance does not prove the browser released all handles. */
static bool await_virtual_hidraw_gone(unsigned wait_ms) {
  int64_t start = time_ms();
  if (start < 0) return false;
  for (;;) {
    char name[64] = {0};
    if (!virtual_hidraw(name, sizeof(name))) return true;
    int64_t now = time_ms();
    if (now < 0 || now - start >= (int64_t)wait_ms ||
        pcsc_fido_daemon_stop_requested()) return false;
    const struct timespec sleep_for = {.tv_sec=0, .tv_nsec=100000000};
    (void)nanosleep(&sleep_for, NULL);
  }
}

int main(int argc, char **argv) {
  nfc_runtime_mode_t mode = {0};
  if (!nfc_runtime_mode_parse(argc, argv, &mode)) {
    fputs("Usage: hp-elitebook-nfc-bridge --auto-webauthn-continuous --allow-webauthn-auth-registration\n", stderr);
    return 2;
  }
  // Fixed general-WebAuthn runtime policy.
  nfc_bridge_set_localhost_browser_enabled(mode.allow_localhost_browser);
  nfc_bridge_set_pin_readonly_enabled(mode.allow_pin_readonly);
  nfc_bridge_set_pin_session_preflight_enabled(mode.pin_session_preflight);
  nfc_bridge_set_pin_token_localhost_enabled(mode.pin_token_localhost);
  nfc_bridge_set_pin_compat_localhost_enabled(mode.pin_compat_localhost);
  nfc_bridge_set_general_webauthn_enabled(mode.general_webauthn);
  (void)setenv("HP_NFC_IDLE_30M","1",1);
  (void)setenv("PCSC_FIDO_RATE_EXCHANGE","50",1);
  (void)setenv("PCSC_FIDO_RATE_CTAPHID","150",1);
  int status = 1;
  bool created = false;
  bool signals = false;
  char hidraw[64] = {0};
  if (geteuid() == 0 || !only_net_admin_effective() ||
      !obtain_group_uhid_fd3(true)) {
    fputs("REFUSED: requires ordinary UID, only effective CAP_NET_ADMIN, and validated UHID fd 3.\n",stderr);
    return 2;
  }
  puts("NFC_BRIDGE_READY: FIDO2/U2F authentication and registration enabled.");
  puts("GENERAL_CTAP_TIMING: initial 15s, active 60s, NFC/PIN input 45s, completion inactivity 10s.");
  puts("GENERAL_IDLE_NOTICE: 30 minute informational heartbeat; NFC polling continuous.");
  fflush(stdout);
  pcsc_fido_daemon_reset_stop_request();
  pcsc_fido_rate_limit_reset();
  if (!pcsc_fido_daemon_signals_init()) {
    fputs("BRIDGE_SIGNAL_SETUP_FAILED: unable to initialise shutdown signal handling.\n", stderr);
    goto out;
  }
  signals = true;
  unsigned long long cycle=0u;
  bool require_quiet=false; // only after a completed automatic UHID session
  // Count completed UHID lifecycles, not empty NFC polling intervals.
  for (;;) {
    printf("AUTO_CYCLE_%llu_WAITING_FOR_PRESENTATION\n",cycle+1u);
    fflush(stdout);
    {
      // Continuous mode must not repeatedly STOP/START NFC while the
      // operator is idle. 0 selects a single stop-responsive steady poll.
      // The installed bridge uses unbounded, stop-responsive idle discovery.
      const unsigned discovery_ms = 0u;
      int triggered=require_quiet ?
          nfc_auto_trigger_guarded(discovery_ms) :
          nfc_auto_trigger_once(discovery_ms);
      if(triggered!=1) {
        // NFC discovery failures, including EBUSY after a controller
        // fault, must not cause systemd to hammer the same device repeatedly.
        // Exit 75 is explicitly non-restartable in the system unit.
        // Normal interruption retains clean exit semantics.
        status=nfc_recovery_exit_code(triggered);
        if(status==NFC_RECOVERY_STOP_EXIT) {
          fputs("NFC_FAIL_CLOSED: discovery or polling stopped unexpectedly; "
                "automatic restart suppressed (exit 75). Inspect kernel "
                "journal before manual recovery. No driver reset attempted.\n",stderr);
        }
        printf("AUTO_CYCLE_%llu_NO_UHID: %s\n",cycle+1u,
               triggered==0 ? "NFC discovery timed out or ended" :
               triggered==-2 ? "stop requested" : "NFC error");
        goto out;
      }
    }
    if (pcsc_fido_daemon_stop_requested()) {
      puts("NFC_STOP_REQUESTED: before virtual HID creation.");
      status=0;
      goto out;
    }
    nfc_auto_bridge_event_reset();
    if (!pcsc_fido_daemon_create_uhid_device(3)) {
      fputs("UHID_CREATE_FAILED: kernel rejected device creation.\n", stderr);
      goto out;
    }
    created = true;
    const int64_t start = time_ms();
    if (start < 0) goto out;
    printf("UHID_CREATE2: waiting up to %d ms for virtual HID device.\n", START_MS);
    fflush(stdout);
    pcsc_fido_daemon_pending_request_t pending = {0};
    pcsc_fido_daemon_pending_request_reset(&pending);
    const uint32_t assigned_cid = PCSC_FIDO_DEFAULT_ASSIGNED_CID;
    const pcsc_fido_daemon_request_context_t ctx = {.fd=3, .assigned_cid=&assigned_cid};
    const pcsc_fido_daemon_uhid_poll_ctx_t poll_ctx = {.uhid_fd=3, .poll_timeout_ms=100};
    bool available = false;
    bool loop_error = false;
    bool auth_start_logged = false;
    int64_t last_assertion_logged = 0;
    for (;;) {
      int64_t elapsed = time_ms() - start;
      if (nfc_runtime_mode_should_stop(&mode, elapsed,
                                       pcsc_fido_daemon_stop_requested())) break;
      const int64_t now=time_ms();
      const int64_t auth_started=nfc_auto_bridge_event_started_ms();
      if (auth_started>0 && !auth_start_logged) {
        printf("AUTH_TIMING_START: browser request started %lldms after virtual HID creation.\n",
               (long long)(auth_started-start));
        auth_start_logged=true;
      }
      const int64_t user_present=nfc_auto_bridge_event_user_present_ms();
      if (user_present>0 && user_present!=last_assertion_logged &&
          auth_started>0 && user_present>=auth_started) {
        int64_t used=user_present-auth_started;
        printf("AUTH_TIMING_ASSERTION: UP=1 UV=1 at +%lldms; ~%lldms remaining (website acceptance not confirmed).\n",
               (long long)used,(long long)(used<GENERAL_ACTIVE_MS ? GENERAL_ACTIVE_MS-used : 0));
        last_assertion_logged=user_present;
      }
      if (!pending.active &&
          nfc_auto_bridge_event_completion_grace_expired(now,GENERAL_COMPLETION_GRACE_MS)) {
        puts("AUTO_COMPLETION_GRACE_ENDED: 10s without further authentication activity; retiring virtual HID.");
        break;
      }
      if (nfc_auto_window_expired(
              now,start,auth_started,
              NFC_AUTO_INITIAL_MS,GENERAL_ACTIVE_MS)) {
        puts(auth_started ?
             "AUTO_ACTIVE_WINDOW_ENDED: authentication window expired; retiring virtual HID." :
             "AUTO_INITIAL_WINDOW_ENDED: no approved browser authentication command received before timeout.");
        break;
      }
      if (!available && virtual_hidraw(hidraw, sizeof(hidraw))) {
        available = true;
        printf("UHID_READY: /dev/%s available.\n", hidraw);
        fflush(stdout);
      }
      if (!available && elapsed > START_MS) {
        fputs("UHID_READY_TIMEOUT: virtual HID device not observed before deadline.\n", stderr);
        loop_error=true;
        break;
      }
      nfc_bridge_pin_session_expire();
      int rv = pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx);
      if (rv != 0) {
        if (rv < 0) {fputs("UHID_EVENT_FAILED: virtual HID event handling failed.\n", stderr);loop_error=true;}
        break;
      }
    }
    pcsc_fido_daemon_pending_request_reset(&pending);
    pcsc_fido_bridge_reset();
    if (available && !loop_error) {
      puts("UHID_SESSION_END: observation window ended; cleaning up.");
      status = 0;
    } else {
      status = 1;
    }
    // For repeated cycles, destroy UHID without closing protected FD3.
    // The same process and fd must remain available for the next CREATE2.
    pcsc_fido_daemon_destroy_uhid_device(3);
    puts("UHID_DESTROY: requested; descriptor retained for next authentication cycle.");
    created = false;
    if (status!=0 || pcsc_fido_daemon_stop_requested()) goto out;
    printf("AUTO_CYCLE_%llu_FINISHED\n",cycle+1u);
    fflush(stdout);
    {
      if (!await_virtual_hidraw_gone(5000u)) {
        fputs("UHID_CLEANUP_UNCONFIRMED: virtual device still visible; next cycle refused.\n", stderr);
        status=1;
        goto out;
      }
      require_quiet=true;
      puts("AUTO_REARM_BEGIN: held-key suppression armed; await AUTO_REARM_READY before next fresh tap.");
      puts("NFC_REARM_NOTICE: key removal is not hardware-verified; keep authenticator away until rearm is ready.");
      fflush(stdout);
    }
    ++cycle;
  }
out:

  if (created) {
    pcsc_fido_daemon_destroy_uhid_device(3);
    puts("UHID_DESTROY: requested during shutdown; closing descriptor.");
  }
  if (signals) pcsc_fido_daemon_signals_shutdown();
  close(3);
  return status;
}
