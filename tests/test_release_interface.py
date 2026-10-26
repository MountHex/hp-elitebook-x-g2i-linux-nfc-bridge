# SPDX-License-Identifier: MIT
# Offline source-interface checks; do not operate systemd or NFC hardware.
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class SourceInterfaceTests(unittest.TestCase):
    def test_shell_scripts_have_valid_syntax(self):
        p = subprocess.run(['bash','-n',
            'tools/common.sh', 'tools/install.sh', 'tools/uninstall.sh'], cwd=ROOT)
        self.assertEqual(p.returncode, 0)

    def test_privileged_scripts_check_root_before_host_actions(self):
        for name in ('tools/install.sh', 'tools/uninstall.sh'):
            script = (ROOT / name).read_text()
            self.assertIn('require_systemd_root', script)
            self.assertLess(script.index('require_systemd_root'),
                            script.index('select_desktop'))
            self.assertNotIn('HOLD: release install/uninstall', script)

    def test_privileged_scripts_refuse_nonroot_execution(self):
        # Never run live installers inside a root-owned test environment.
        import os
        if os.geteuid() == 0:
            self.skipTest('Privileged installer execution is excluded from tests')
        for name in ('install.sh', 'uninstall.sh'):
            result = subprocess.run(['bash', str(ROOT / 'tools' / name)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('Run using sudo', result.stderr)

    def test_downstream_modified_files_keep_attribution(self):
        changed = [
            "upstream/include/pcsc_fido/browser_daemon.h",
            "upstream/include/pcsc_fido/daemon_policy.h",
            "upstream/include/pcsc_fido/daemon_signals.h",
            "upstream/include/pcsc_fido/daemon_uhid_loop.h",
            "upstream/include/pcsc_fido/pcsc_bridge.h",
            "upstream/include/pcsc_fido/pcsc_err.h",
            "upstream/src/apdu.c",
            "upstream/src/cbor_util.c",
            "upstream/src/daemon_policy.c",
            "upstream/src/daemon_rate_limit.c",
            "upstream/src/daemon_request_handler.c",
            "upstream/src/daemon_signals.c",
            "upstream/src/daemon_uhid_loop.c",
            "upstream/src/exchange_orchestrator.c",
            "upstream/src/pcsc_log.c",
            "upstream/src/request_assembly.c",
            "upstream/src/uhid_transport.c",
        ]
        notices = (ROOT / 'THIRD-PARTY-NOTICES.md').read_text()
        for name in changed:
            with self.subTest(source=name):
                content = (ROOT / name).read_text()
                self.assertTrue(content.startswith('// Modified downstream in 2026'))
                self.assertIn('// SPDX-License-Identifier: Apache-2.0', content[:500])
                self.assertIn('Copyright (C) 2026 Nero Duality, LLC.', content[:700])
                self.assertIn(f'`{name}`', notices)
        for required in (
            'upstream/licenses/pcsc-fido-Apache-2.0.txt',
            'upstream/licenses/pcsc-fido-NOTICE.txt',
            'upstream/licenses/libfido2-BSD-2-Clause.txt',
        ):
            self.assertTrue((ROOT / required).is_file())

    def test_virtual_hid_identity_matches_sysfs_lookup(self):
        identity = (ROOT / 'bridge_identity.h').read_text()
        create = (ROOT / 'upstream/src/uhid_transport.c').read_text()
        discover = (ROOT / 'bridge_main.c').read_text()
        self.assertIn('NFC_BRIDGE_UHID_NAME "HP EliteBook X G2i Linux NFC Bridge"', identity)
        self.assertIn('NFC_BRIDGE_UHID_PHYS "hp-elitebook-nfc-bridge/uhid"', identity)
        self.assertIn('NFC_BRIDGE_UHID_NAME', create)
        self.assertIn('"HID_NAME=" NFC_BRIDGE_UHID_NAME', discover)
        self.assertNotIn('pcsc-fido virtual NFC bridge', create + discover)

    def test_unused_upstream_always_mode_removed_without_active_polling_loss(self):
        impl = (ROOT / 'upstream/src/daemon_uhid_loop.c').read_text()
        header = (ROOT / 'upstream/include/pcsc_fido/daemon_uhid_loop.h').read_text()
        main = (ROOT / 'bridge_main.c').read_text()
        for source in (impl, header):
            self.assertNotIn('pcsc_fido_daemon_run_always_mode', source)
        self.assertNotIn('virtual FIDO HID bridge ready; tap NFC key', impl)
        for required in ('void pcsc_fido_daemon_handle_uhid_event(',
                         'int pcsc_fido_daemon_poll_uhid_event('):
            self.assertIn(required, impl)
        self.assertIn('pcsc_fido_daemon_poll_uhid_event(&poll_ctx, &pending, &ctx)', main)
        self.assertIn('pcsc_fido_daemon_create_uhid_device(3)', main)
        self.assertIn('pcsc_fido_daemon_destroy_uhid_device(3)', main)

    def test_approved_remaining_logging_and_error_metadata(self):
        messages = {
            'bridge_main.c': [
                'NFC_STOP_REQUESTED: before virtual HID creation.',
                'BRIDGE_SIGNAL_SETUP_FAILED: unable to initialise shutdown signal handling.',
                'UHID_CREATE_FAILED: kernel rejected device creation.',
                'UHID_READY_TIMEOUT: virtual HID device not observed before deadline.',
                'UHID_EVENT_FAILED: virtual HID event handling failed.',
                'UHID_CLEANUP_UNCONFIRMED: virtual device still visible; next cycle refused.',
                'UHID_DESTROY: requested during shutdown; closing descriptor.',
            ],
            'nfc_auto_trigger.c': [
                'NFC_IDLE_WAITING: no target event; polling session remains open (RF state unverified).',
                'perror("NFC_NETLINK_SOCKET_OPEN_FAILED")',
            ],
            'upstream/src/daemon_uhid_loop.c': [
                'CTAPHID_REQUEST_ASSEMBLY_FAILED',
                'UHID_READ_FAILED',
                'UHID_POLL_FAILED',
            ],
            'upstream/src/daemon_request_handler.c': [
                'NFC_EXCHANGE_FAILED: %s',
                'WebAuthn operation complete; clearing bridge session state',
            ],
            'upstream/src/exchange_orchestrator.c': [
                'UHID client closed during NFC exchange',
                'CTAPHID CANCEL received during NFC exchange',
                'stop requested during NFC exchange',
                'NFC exchange still running cmd=0x%02X elapsed~%us',
            ],
            'upstream/src/uhid_transport.c': ['UHID_WRITE_FAILED: %s'],
            'upstream/src/daemon_rate_limit.c': [
                'Invalid %s; using default %u',
            ],
        }
        for name, snippets in messages.items():
            source = (ROOT / name).read_text()
            for snippet in snippets:
                with self.subTest(filename=name, message=snippet):
                    self.assertIn(snippet, source)
        rate_limit = (ROOT / 'upstream/src/daemon_rate_limit.c').read_text()
        self.assertNotIn('invalid %s=%s; using default', rate_limit)
        self.assertNotIn('v, default_value', rate_limit)
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertNotIn('perror("NETLINK_GENERIC socket")', trigger)
        # Failure branches still report system error details.
        self.assertIn('strerror(errno)', (ROOT / 'upstream/src/daemon_uhid_loop.c').read_text())
        self.assertIn('strerror(errno)', (ROOT / 'upstream/src/uhid_transport.c').read_text())

    def test_nfc_exchange_error_wording_preserves_api_identifiers(self):
        orchestrator = (ROOT / 'upstream/src/exchange_orchestrator.c').read_text()
        err_header = (ROOT / 'upstream/include/pcsc_fido/pcsc_err.h').read_text()
        for message in (
            'failed to initialize NFC exchange mutex',
            'failed to start NFC exchange thread',
        ):
            self.assertIn(message, orchestrator)
        self.assertIn('#define PCSC_FIDO_ERR_MSG_RATE_LIMIT "NFC exchange rate limit exceeded"',
                      err_header)
        self.assertNotIn('PC/SC exchange mutex', orchestrator)
        self.assertNotIn('PC/SC exchange thread', orchestrator)
        self.assertNotIn('PC/SC exchange rate limit exceeded', err_header)
        # Diagnostic wording changes must not rename inherited upstream APIs.
        self.assertIn('pcsc_fido_daemon_run_exchange_with_keepalive(', orchestrator)
        self.assertIn('PCSC_FIDO_ERR_MSG_RATE_LIMIT', err_header)

    def test_startup_messages_match_release_policy(self):
        source = (ROOT / 'bridge_main.c').read_text()
        for required in (
            'NFC_BRIDGE_READY: FIDO2/U2F authentication and registration enabled.',
            'GENERAL_CTAP_TIMING: initial 15s, active 60s, NFC/PIN input 45s, completion inactivity 10s.',
            'GENERAL_IDLE_NOTICE: 30 minute informational heartbeat; NFC polling continuous.',
        ):
            self.assertIn(required, source)
        for unnecessary in ('PIN set/change, reset, credential management',
                            'NFC_SECURITY:', 'browser registration enabled.'):
            self.assertNotIn(unnecessary, source)

    def test_nfc_netlink_and_device_up_errors_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('NFC_NETLINK_SOCKET_ERROR: communication failure.', trigger)
        self.assertIn('NFC_DEV_UP_FAILED: code=%d', trigger)
        self.assertNotIn('NETLINK_GENERIC socket error', trigger)
        self.assertNotIn('NFC DEV_UP failed:', trigger)
        # Keep both failure branches distinguishable and fail without retry.
        self.assertIn('NFC START_POLL failed: kernel errno=%d (%s); no retry', trigger)
        self.assertIn('NFC START_POLL failed: transport/timeout/interruption=%d; no retry', trigger)
        self.assertIn('if(r>0)', trigger)
        self.assertIn('if(r==-2) status=-2;', trigger)

    def test_nfc_netlink_setup_failure_messages_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('perror("NFC_NETLINK_BIND_FAILED")', trigger)
        self.assertIn('NFC_FAMILY_LOOKUP_FAILED: unable to resolve NFC family or event group.', trigger)
        self.assertIn('perror("NFC_EVENT_SUBSCRIBE_FAILED")', trigger)
        for old in ('NETLINK_GENERIC bind', 'NFC family lookup failed.',
                    'subscribe NFC events'):
            self.assertNotIn(old, trigger)
        # Keep socket/bind, family/group lookup and subscription failures separate.
        self.assertIn('if(bind(s.fd,(const struct sockaddr *)&addr,sizeof addr)<0)', trigger)
        self.assertIn('if(r || !s.family || !s.group)', trigger)
        self.assertIn('if(setsockopt(s.fd,SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,&s.group,sizeof s.group)<0)', trigger)

    def test_nfc_command_transmission_errors_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('perror("NFC_COMMAND_SEND_FAILED")', trigger)
        self.assertIn('perror("NFC_GET_TARGET_SEND_FAILED")', trigger)
        self.assertIn('NFC_GET_TARGET_REJECTED: %s (code %d)', trigger)
        for obsolete in ('perror("send NFC command")',
                         'perror("send NFC_CMD_GET_TARGET")',
                         'NFC_CMD_GET_TARGET rejected:'):
            self.assertNotIn(obsolete, trigger)
        # Error branches still stop their call paths, and rejected ACKs retain details.
        self.assertIn('if(!send_cmd(s,s->family,NFC_GENL_VERSION,cmd,NLM_F_ACK,&seq))', trigger)
        self.assertIn('if(!send_cmd(s,s->family,NFC_GENL_VERSION,NFC_CMD_GET_TARGET,NLM_F_DUMP,&seq))', trigger)
        self.assertIn('strerror(n->kernel_error),n->kernel_error', trigger)

    def test_nfc_event_packet_errors_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('NFC_EVENT_PACKET_INVALID: oversized or empty packet.', trigger)
        self.assertIn('NFC_EVENT_PACKET_INVALID: malformed generic-netlink packet.', trigger)
        self.assertNotIn('Oversized or empty NFC event packet', trigger)
        self.assertNotIn('Malformed NFC generic-netlink packet', trigger)
        # Preserve the two separate rejection conditions and their error return.
        self.assertIn('if((size_t)n>sizeof buf || n==0)', trigger)
        self.assertIn('if(!nfc_event_decode(buf,(size_t)n,s->family,notes,32u,count))', trigger)
        self.assertIn('perror("NFC_NETLINK_POLL_FAILED")', trigger)
        self.assertIn('perror("NFC_NETLINK_RECV_FAILED")', trigger)

    def test_nfc_detection_messages_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('NFC_START_POLL_OK: waiting for NFC authenticator.', trigger)
        self.assertIn('FIDO_SELECT_OK: compatible NFC authenticator detected.', trigger)
        self.assertNotIn('present a FIDO YubiKey; UHID is not yet visible.', trigger)
        self.assertNotIn('validated compatible NFC authenticator; closing preflight connection.', trigger)
        # Preserve the distinct guarded rearm diagnostic and its timing behaviour.
        self.assertIn('NFC_START_POLL_OK: checking %u ms quiet interval;', trigger)

    def test_uhid_creation_messages_use_approved_wording(self):
        source = (ROOT / 'bridge_main.c').read_text()
        self.assertIn('UHID_CREATE2: waiting up to %d ms for virtual HID device.', source)
        self.assertIn('UHID_READY: /dev/%s available.', source)
        self.assertNotIn('UHID_CREATE2 submitted. Waiting up to', source)
        self.assertNotIn('Kernel exposed /dev/%s; bridge active; fixed registration', source)
        self.assertNotIn('GENERAL_WEBAUTHN_ACTIVE:', source)
        self.assertNotIn('General WebAuthn encrypted PIN token relay enabled', source)

    def test_ctap_event_messages_use_approved_prefixes(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('"CTAP_ALLOWED: ctap=0x%02x sub=0x%02x protocol=%u', source)
        self.assertIn('"CTAP_STATUS: ctap=0x%02x status=0x%03x', source)
        self.assertNotIn('GENERAL_CTAP_ALLOWED:', source)
        self.assertNotIn('GENERAL_CTAP_STATUS:', source)
        # Preserve detailed command metadata without logging CTAP payloads.
        self.assertIn('web.ctap_command,web.pin_subcommand,web.pin_protocol', source)
        self.assertIn('web.ctap_command,ctap_status', source)

    def test_u2f_event_message_uses_approved_wording(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('U2F_ALLOWED: legacy U2F command accepted; payload not logged.', source)
        self.assertNotIn('GENERAL_U2F_ALLOWED:', source)
        # Legacy U2F remains separately classified and handled.
        self.assertIn('if (generic_u2f) fputs(', source)

    def test_assertion_flags_messages_use_general_names(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('"ASSERTION_FLAGS: up=%u uv=%u\\n"', source)
        self.assertIn('"ASSERTION_FLAGS: unavailable\\n"', source)
        self.assertNotIn('PIN_COMPAT_ASSERTION_FLAGS:', source)
        # The CBOR parsing, UP/UV masks and return value are unchanged.
        self.assertIn('(flags&0x01u)?1u:0u,(flags&0x04u)?1u:0u', source)
        self.assertIn('return (flags&0x05u)==0x05u;', source)

    def test_pin_exchange_messages_use_approved_wording(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('"PIN_AGREEMENT_READY: NFC connection retained for next PIN step (45s)."', source)
        self.assertIn('"PIN_TOKEN_RELAYED: encrypted response forwarded; NFC connection retained (45s)."', source)
        self.assertNotIn('PIN_TOKEN_HELD_AFTER_AGREEMENT: follow-up possible (45s).', source)
        self.assertNotIn('GENERAL_PIN_TOKEN_GRANTED:', source)
        # The separate 12-second compatibility branch retains its duration.
        self.assertIn('PIN_AGREEMENT_READY: NFC connection retained for next PIN step (12s).', source)
        self.assertIn('PIN_PREFLIGHT_READY: one read-only follow-up permitted (12s).', source)
        self.assertIn('PIN_TOKEN_RELAYED_LOCALHOST: encrypted response forwarded; assertion window 45s.', source)
        self.assertIn('PIN_TOKEN_RELAYED_LOCALHOST: encrypted response forwarded; NFC connection retained (12s).', source)
        self.assertNotIn('PIN_TOKEN_GRANTED_LOCALHOST:', source)

    def test_pin_expiration_messages_use_approved_wording(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('PIN_COMPAT_SESSION_EXPIRED: held NFC connection closed.', source)
        self.assertIn('PIN_PREFLIGHT_EXPIRED: read-only NFC connection closed.', source)
        self.assertNotIn('PIN_PREFLIGHT_EXPIRED: held NFC connection closed, no PIN operations.', source)
        # The same bounded-session expiration and socket closure remain.
        self.assertIn('!nfc_pin_session_policy_valid(&pin_policy,pin_clock_ms())', source)
        self.assertIn('pin_held_close();', source)

    def test_session_reuse_messages_use_approved_wording(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('PIN_SESSION_REUSE: using same NFC connection for token/assertion.', source)
        self.assertIn('PIN_PREFLIGHT_REUSE: using same NFC connection for read-only command.', source)
        self.assertIn('AUTH_SESSION_RETAINED: NFC connection retained for browser continuation (45s).', source)
        self.assertNotIn('GENERAL_AUTH_SESSION_HELD:', source)

    def test_next_assertion_messages_use_approved_wording(self):
        source = (ROOT / 'nfc_pcsc_bridge.c').read_text()
        self.assertIn('NEXT_ASSERTIONS_PENDING: NFC connection retained for additional assertions (45s).', source)
        self.assertIn('NEXT_ASSERTION_REUSE: NFC connection retained for additional assertions (45s).', source)
        self.assertNotIn('GENERAL_NEXT_ASSERTIONS_PENDING:', source)
        self.assertNotIn('GENERAL_NEXT_ASSERTION_REUSE:', source)
        # These are log-only changes; the two session-retention branches remain.
        self.assertIn('generic_assertion && ctap_status==0u', source)
        self.assertIn('generic_next && ctap_status==0u', source)

    def test_auth_timing_messages_are_concise(self):
        source = (ROOT / 'bridge_main.c').read_text()
        self.assertIn('AUTH_TIMING_START: browser request started %lldms after virtual HID creation.', source)
        self.assertIn('AUTH_TIMING_ASSERTION: UP=1 UV=1 at +%lldms; ~%lldms remaining (website acceptance not confirmed).', source)
        self.assertNotIn('approved browser request began', source)
        self.assertNotIn('not RP confirmation', source)
        # Timing calculations and 60-second window must remain in place.
        self.assertIn('auth_started-start', source)
        self.assertIn('used=user_present-auth_started', source)
        self.assertIn('GENERAL_ACTIVE_MS-used', source)

    def test_completion_and_uhid_cleanup_messages_are_concise(self):
        source = (ROOT / 'bridge_main.c').read_text()
        for required in (
            'AUTO_COMPLETION_GRACE_ENDED: 10s without further authentication activity; retiring virtual HID.',
            'UHID_SESSION_END: observation window ended; cleaning up.',
            'UHID_DESTROY: requested; descriptor retained for next authentication cycle.',
        ):
            self.assertIn(required, source)
        self.assertNotIn('10s without approved NFC authentication work after UP=1 UV=1;', source)
        self.assertNotIn('UHID_DESTROY requested; descriptor remains open until process exit.', source)
        # Preserve inactive timeout and UHID destruction/rearm call order.
        self.assertIn('nfc_auto_bridge_event_completion_grace_expired(now,GENERAL_COMPLETION_GRACE_MS)', source)
        self.assertIn('pcsc_fido_daemon_destroy_uhid_device(3);', source)
        self.assertIn('AUTO_REARM_BEGIN:', source)

    def test_authentication_window_timeout_messages_use_approved_wording(self):
        source = (ROOT / 'bridge_main.c').read_text()
        self.assertIn(
            'AUTO_INITIAL_WINDOW_ENDED: no approved browser authentication command received before timeout.',
            source)
        self.assertIn(
            'AUTO_ACTIVE_WINDOW_ENDED: authentication window expired; retiring virtual HID.',
            source)
        self.assertNotIn('no approved browser credential command started.', source)
        self.assertNotIn('retiring UHID after browser command.', source)
        # Keep the existing initial/active window check and completion order.
        self.assertIn('nfc_auto_window_expired(', source)
        self.assertIn('NFC_AUTO_INITIAL_MS,GENERAL_ACTIVE_MS', source)

    def test_rearm_messages_use_approved_wording(self):
        main = (ROOT / 'bridge_main.c').read_text()
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('NFC_REARM_NOTICE: key removal is not hardware-verified; keep authenticator away until rearm is ready.', main)
        self.assertIn('AUTO_REARM_READY: quiet interval observed; ready for next NFC authentication.', trigger)
        self.assertNotIn('IMPORTANT: key absence is NOT hardware-verified;', main)
        self.assertNotIn('browser may now request sign-in, then tap YubiKey.', trigger)
        # The quiet-interval gate and rearm start remain unchanged.
        self.assertIn('AUTO_REARM_BEGIN:', main)
        self.assertIn('NFC_REARM_QUIET_MS', trigger)
        self.assertIn('AUTO_QUIET_INCOMPLETE:', trigger)

    def test_held_key_suppression_messages_use_approved_wording(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn('AUTO_HELD_SUPPRESSED: early rediscovery; virtual HID creation suppressed.', trigger)
        self.assertIn('AUTO_QUIET_INCOMPLETE: quiet interval not confirmed; virtual HID not created.', trigger)
        self.assertIn('AUTO_GUARD_RETRY: waiting for a target-free interval.', trigger)
        self.assertNotIn('virtual device will NOT be created.', trigger)
        self.assertNotIn('AUTO_QUIET_INCOMPLETE: no virtual key created.', trigger)
        # Preserve quiet-interval, suppression and retry behaviour.
        self.assertIn('nfc_rearm_quiet_complete(', trigger)
        self.assertIn('suppressed>NFC_REARM_MAX_SUPPRESSIONS', trigger)
        self.assertIn('await_held_loss(active_fd,held_deadline)', trigger)

    def test_uhid_client_disconnection_log_is_precise(self):
        source = (ROOT / 'upstream/src/daemon_uhid_loop.c').read_text()
        self.assertIn('UHID client closed; resetting bridge request state.', source)
        self.assertNotIn('UHID client closed; resetting authenticator session', source)
        # The actual reset handlers remain intact.
        self.assertIn('pcsc_fido_daemon_pending_request_reset(pending);', source)
        self.assertIn('pcsc_fido_bridge_reset();', source)

    def test_held_key_communication_loss_message_is_precise(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        self.assertIn(
            'AUTO_HELD_COMMUNICATION_LOST: NFC communication lost; removal unconfirmed; checking quiet interval.',
            trigger)
        self.assertNotIn('physical removal is possible, not proven; checking quiet interval again.', trigger)
        # The same held-key probe and quiet-interval gating must remain in place.
        self.assertIn('if(selected!=NFC_APDU_OK)', trigger)
        self.assertIn('await_held_loss(active_fd,held_deadline)', trigger)

    def test_fail_closed_recovery_messages_have_consistent_prefix(self):
        trigger = (ROOT / 'nfc_auto_trigger.c').read_text()
        main = (ROOT / 'bridge_main.c').read_text()
        self.assertIn('NFC_FAIL_CLOSED: excessive ambiguous rediscoveries.', trigger)
        self.assertIn('NFC_FAIL_CLOSED: held-key probe timed out or failed.', trigger)
        self.assertIn('NFC_FAIL_CLOSED: discovery or polling stopped unexpectedly;', main)
        self.assertNotIn('"FAIL_CLOSED: excessive ambiguous rediscoveries.', trigger)
        self.assertNotIn('"FAIL_CLOSED: held-key probe timed out or failed.', trigger)
        # Do not change fail-closed branching or held-key probe logic.
        self.assertIn('suppressed>NFC_REARM_MAX_SUPPRESSIONS', trigger)
        self.assertIn('await_held_loss(active_fd,held_deadline)', trigger)

    def test_success_messages_are_concise(self):
        install = (ROOT / 'tools/install.sh').read_text()
        uninstall = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertIn("echo 'Installation complete.'", install)
        self.assertIn("echo 'Uninstallation complete.'", uninstall)
        self.assertNotIn('browser NFC authentication before considering', install)
        self.assertNotIn('unrelated files preserved', uninstall)

    def test_fixed_interface_and_separate_driver(self):
        make = (ROOT / 'Makefile').read_text()
        self.assertIn('install:\n\t@bash tools/install.sh', make)
        self.assertIn('uninstall:\n\t@bash tools/uninstall.sh', make)
        self.assertIn('test:\n', make)
        self.assertNotIn('dkms', make.lower())
        self.assertFalse((ROOT/'driver').exists())
        self.assertFalse((ROOT/'installer').exists())
        self.assertFalse((ROOT/'private_validation').exists())

    def test_release_executable_identity(self):
        executable = 'hp-elitebook-nfc-bridge'
        make = (ROOT/'Makefile').read_text()
        self.assertIn(f'{executable}: $(SOURCES) $(HEADERS)', make)
        self.assertIn(f'make -s -C "$rootdir" -q {executable}',
                      (ROOT/'tools/install.sh').read_text())
        service = (ROOT/'deploy/hp-elitebook-nfc-bridge.service.in').read_text()
        self.assertIn(f'/{executable} --auto-webauthn-continuous', service)
        self.assertIn(f'"$libdir/{executable}"',
                      (ROOT/'tools/common.sh').read_text())
        self.assertTrue((ROOT/'bridge_main.c').is_file())

    def test_recovery_policy_fails_closed_without_hardware(self):
        with tempfile.TemporaryDirectory() as folder:
            source = pathlib.Path(folder)/'recovery_test.c'
            source.write_text('''
#include "nfc_recovery_policy.h"
int main(void) {
  return nfc_recovery_exit_code(-2) != 0 ||
         nfc_recovery_exit_code(-1) != NFC_RECOVERY_STOP_EXIT ||
         nfc_recovery_exit_code(0) != NFC_RECOVERY_STOP_EXIT;
}
''')
            executable = pathlib.Path(folder)/'recovery_test'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I', str(ROOT), str(source),
                            str(ROOT/'nfc_recovery_policy.c'), '-o',str(executable)],
                           check=True)
            subprocess.run([str(executable)], check=True)

    def test_conflict_detection_preserves_other_bridge_versions(self):
        common = (ROOT/'tools/common.sh').read_text()
        install = (ROOT/'tools/install.sh').read_text()
        self.assertIn('"$libdir"/*|/usr/local/libexec/hp-nfc-bridge-*/*', common)
        self.assertIn('/usr/local/libexec/hp-nfc-bridge-*/*', install)
        self.assertIn('bridge_running || systemctl is-active', install)

    def test_retain_restricted_templates(self):
        service=(ROOT/'deploy/hp-elitebook-nfc-bridge.service.in').read_text()
        self.assertIn('User=hp-nfc-bridge', service)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN', service)
        self.assertIn('RestartPreventExitStatus=75', service)
        self.assertIn('ConditionPathExists=/sys/class/nfc/nfc0', service)
        self.assertNotIn('User=root', service)
        rule=(ROOT/'deploy/49-hp-elitebook-nfc-bridge.rules.in').read_text()
        self.assertIn('subject.user !== "__LOGIN_NAME__"',rule)
        self.assertIn('hp-elitebook-nfc-bridge.service',rule)
        self.assertIn('verb !== "start" && verb !== "stop"',rule)

    def test_no_background_controller_or_private_development_source(self):
        self.assertFalse((ROOT/'private_validation').exists())
        for name in ('tools/install.sh','tools/uninstall.sh'):
            text=(ROOT/name).read_text()
            self.assertNotIn('modprobe ',text)
            self.assertNotIn('rmmod ',text)
            self.assertNotIn('dkms ',text)
            self.assertNotIn('unbind',text)


    def test_header_changes_are_build_dependencies(self):
        make = (ROOT / 'Makefile').read_text()
        self.assertIn('HEADERS = $(wildcard *.h upstream/include/pcsc_fido/*.h)', make)
        self.assertIn('hp-elitebook-nfc-bridge: $(SOURCES) $(HEADERS)', make)
        self.assertIn('$(CC) $(CFLAGS) $(INCLUDE) $(SOURCES) -o $@', make)
        self.assertIn('make -s -C "$rootdir" -q hp-elitebook-nfc-bridge',
                      (ROOT / 'tools/install.sh').read_text())

    def test_receipt_verifies_exact_fixed_paths_including_spaces(self):
        # Execute only pure helper functions against disposable local files.
        # No root, systemd, host-installed paths or NFC device access.
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp)
            a = p / 'plain'
            b = p / 'path with spaces'
            a.write_text('original')
            b.write_text('another')
            record = p / 'record'
            record.mkdir()
            script = r"""
                set -euo pipefail
                source "$1/tools/common.sh"
                recorddir="$2/record"
                targets=("$2/plain" "$2/path with spaces")
                receipt_hashes > "$recorddir/files.sha256"
                receipt_matches || exit 11
                printf 'changed' > "${targets[1]}"
                if receipt_matches; then exit 12; fi
                printf 'another' > "${targets[1]}"
                printf 'tampered' >> "$recorddir/files.sha256"
                if receipt_matches; then exit 13; fi
            """
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), temp],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstaller_only_uses_pinned_destinations(self):
        text = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertIn('receipt_matches ||', text)
        self.assertNotIn('recorded_names=', text)
        self.assertNotIn('sha256sum --check', text)
        self.assertIn('rm -- "${targets[@]:0:5}"', text)
        self.assertIn('runuser -u "$desktop" -- rm -- "$userpath"', text)

    def test_installer_never_invokes_kernel_driver_changes(self):
        for path in (ROOT / 'tools').glob('*.sh'):
            text = path.read_text()
            for forbidden in ('modprobe ', 'rmmod ', 'dkms ', '/sys/bus/i2c/drivers/', 'mokutil --import'):
                self.assertNotIn(forbidden, text, (path.name, forbidden))

    def test_user_unit_parents_reject_symlinks(self):
        script = r"""
            set -euo pipefail
            source "$1/tools/common.sh"
            home="$2/home"
            mkdir -p "$home/.config"
            check_user_unit_parents
            mkdir -p "$2/other"
            ln -s "$2/other" "$home/.config/systemd"
            if check_user_unit_parents >/dev/null 2>&1; then exit 19; fi
            rm "$home/.config/systemd"
            mkdir -p "$home/.config/systemd/user"
            check_user_unit_parents
        """
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), temp],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        uninstall = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertLess(uninstall.index('runuser -u "$desktop" -- rm -- "$userpath"'),
                        uninstall.index('rm -- "${targets[@]:0:5}"'))

    def test_uninstaller_defers_removal_until_bridge_is_stopped(self):
        text = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertLess(text.index('userctl disable --now'), text.index('systemctl stop "$unit"'))
        self.assertLess(text.index('systemctl stop "$unit"'), text.index('bridge_running ||'))
        self.assertLess(text.index('bridge_running ||'), text.index('rm -- "${targets[@]:0:5}"'))


    def test_all_core_commands_declared_before_file_changes(self):
        install = (ROOT/'tools/install.sh').read_text()
        uninstall = (ROOT/'tools/uninstall.sh').read_text()
        for cmd in ('chmod','mkdir','readlink','install','make'):
            self.assertIn(cmd, install.split('select_desktop')[0])
        for cmd in ('cat','readlink','rm','rmdir'):
            self.assertIn(cmd, uninstall.split('select_desktop')[0])

    def test_prerequisite_commands_fail_before_installing_files(self):
        script = r"""
            source "$1/tools/common.sh"
            require_programs bash nfc-test-command-deliberately-not-installed
        """
        proc = subprocess.run(['bash', '-c', script, '--', str(ROOT)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('Missing required command:', proc.stderr)
        install = (ROOT / 'tools/install.sh').read_text()
        self.assertLess(install.index('require_programs '),
                        install.index('install -d -m 0755 "$libdir"'))

    def test_fresh_install_rejects_generic_legacy_file_patterns(self):
        text = (ROOT / 'tools/install.sh').read_text()
        self.assertIn('/usr/local/libexec/hp-nfc-bridge-*/*', text)
        self.assertIn('/etc/systemd/system/hp-nfc-bridge-*.service', text)
        self.assertIn('/etc/udev/rules.d/*hp-nfc-bridge*.rules', text)
        self.assertIn('/etc/tmpfiles.d/*hp-nfc-bridge*.conf', text)
        # Do not tie conflicts to a particular historical version.
        self.assertNotRegex(text, r'hp-nfc-bridge-[0-9]')


    def test_account_scoped_templates_render_without_unresolved_placeholders(self):
        system = (ROOT / 'deploy/hp-elitebook-nfc-bridge.service.in').read_text()
        polkit = (ROOT / 'deploy/49-hp-elitebook-nfc-bridge.rules.in').read_text()
        rendered_system = system.replace('__LOGIN_UID__', '1234')
        rendered_polkit = polkit.replace('__LOGIN_NAME__', 'review-account')
        self.assertNotIn('__LOGIN_', rendered_system + rendered_polkit)
        self.assertIn('BindsTo=user@1234.service', rendered_system)
        self.assertIn('subject.user !== "review-account"', rendered_polkit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN', rendered_system)
        self.assertIn('if (verb !== "start" && verb !== "stop") return;', rendered_polkit)

    def test_unknown_release_directory_contents_block_uninstall(self):
        uninstall = (ROOT / 'tools/uninstall.sh').read_text()
        common = (ROOT / 'tools/common.sh').read_text()
        self.assertIn('Unexpected files in release directories', uninstall)
        self.assertIn('installed=("$libdir"/*)', common)
        self.assertIn('receipts=("$recorddir"/*)', common)
        self.assertLess(uninstall.index('release_directories_are_exact'),
                        uninstall.index('userctl disable --now'))
        self.assertLess(uninstall.index('release_directories_are_exact'),
                        uninstall.index('rm -- "${targets[@]:0:5}"'))
        self.assertNotIn('receipts[*]', common)


    def test_fresh_install_does_not_adopt_existing_release_directory(self):
        source = (ROOT / 'tools/install.sh').read_text()
        self.assertLess(source.index('release_directory_is_unused'),
                        source.index('install -d -m 0755 "$libdir"'))
        script = r"""
            set -euo pipefail
            source "$1/tools/common.sh"
            libdir="$2/release-dir"
            release_directory_is_unused
            mkdir "$libdir"
            if release_directory_is_unused; then exit 13; fi
            rmdir "$libdir"
            ln -s "$2/elsewhere" "$libdir"
            if release_directory_is_unused; then exit 14; fi
        """
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), temp],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstall_checks_exact_directory_contents(self):
        script = r"""
            set -euo pipefail
            source "$1/tools/common.sh"
            libdir="$2/app files"
            recorddir="$2/record files"
            mkdir "$libdir" "$recorddir"
            targets=("$libdir/hp-elitebook-nfc-bridge")
            printf 'binary' > "${targets[0]}"
            printf 'desktop' > "$recorddir/desktop"
            printf 'checksums' > "$recorddir/files.sha256"
            release_directories_are_exact || exit 11
            printf 'extra' > "$recorddir/strange filename with spaces"
            if release_directories_are_exact; then exit 12; fi
            rm -- "$recorddir/strange filename with spaces"
            printf 'extra' > "$libdir/unexpected"
            if release_directories_are_exact; then exit 13; fi
            rm -- "$libdir/unexpected"
            release_directories_are_exact || exit 14
            rm "$recorddir/desktop"
            ln -s /dev/null "$recorddir/desktop"
            # The caller checks receipt symlinks explicitly before invoking helper.
            [[ -L "$recorddir/desktop" ]] || exit 15
        """
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), temp],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        uninstall = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertIn('! -L "$recorddir/desktop"', uninstall)
        self.assertIn('! -L "$recorddir/files.sha256"', uninstall)

    def test_user_directory_preflight_precedes_privileged_file_changes(self):
        script = (ROOT / 'tools/install.sh').read_text()
        desktop_mkdir = 'runuser -u "$desktop" -- mkdir -p -- "$home/.config/systemd/user"'
        writable = 'runuser -u "$desktop" -- test -w "$home/.config/systemd/user"'
        self.assertEqual(script.count(desktop_mkdir), 1)
        self.assertIn(writable, script)
        self.assertLess(script.index(desktop_mkdir), script.index('useradd --system'))
        self.assertLess(script.index(writable), script.index('install -d -m 0755 "$libdir"'))
        self.assertLess(script.index('check_user_unit_parents', script.index(desktop_mkdir)),
                        script.index(writable))

    def test_existing_service_account_must_not_be_desktop_login(self):
        script = (ROOT / 'tools/install.sh').read_text()
        self.assertIn('"$svc_uid" != "$uid"', script)
        self.assertIn('"$svc_home" != "$home"', script)
        self.assertIn('"$svc_shell" == */nologin', script)

    def test_systemd_prerequisite_not_distro_marker(self):
        common = (ROOT / 'tools/common.sh').read_text()
        install = (ROOT / 'tools/install.sh').read_text()
        uninstall = (ROOT / 'tools/uninstall.sh').read_text()
        self.assertIn('require_systemd_root()', common)
        self.assertIn('/run/systemd/system', common)
        self.assertNotIn('/etc/fedora-release', common + install + uninstall)
        self.assertIn('require_systemd_root', install)
        self.assertIn('require_systemd_root', uninstall)
        self.assertIn('graphical-session.target', install)
        self.assertIn('/etc/polkit-1/rules.d', install)

    def test_selinux_optional_but_enforcing_when_present(self):
        script = r"""
            set -euo pipefail
            source "$1/tools/common.sh"
            restorecon() { :; }
            check_selinux "$2"
        """
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp)
            missing = p / 'absent'
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), str(missing)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            mode = p / 'enforce'
            mode.write_text('1\n')
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), str(mode)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            mode.write_text('0\n')
            result = subprocess.run(['bash', '-c', script, '--', str(ROOT), str(mode)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('not Enforcing', result.stderr)
        common = (ROOT / 'tools/common.sh').read_text()
        self.assertIn('apply_selinux_contexts()', common)
        self.assertNotIn('restorecon \\n', (ROOT / 'tools/install.sh').read_text())

    def test_unit_execs_use_standard_systemd_search_path(self):
        service = (ROOT / 'deploy/hp-elitebook-nfc-bridge.service.in').read_text()
        session = (ROOT / 'deploy/hp-elitebook-nfc-bridge-session.service').read_text()
        self.assertIn('ExecStart=stdbuf ', service)
        self.assertIn('ExecStart=systemctl --system', session)
        self.assertIn('ExecStop=systemctl --system', session)
        self.assertNotIn('ExecStart=/usr/bin/', service + session)
        self.assertIn('PartOf=graphical-session.target', session)
        self.assertIn('WantedBy=graphical-session.target', session)

if __name__ == '__main__':
    unittest.main()
