CC ?= cc
CFLAGS = -std=c2x -Wall -Wextra -Werror -Wpedantic -O1 -pthread -D_POSIX_C_SOURCE=200809L -ffile-prefix-map="$(CURDIR)=." -fdebug-prefix-map="$(CURDIR)=."
INCLUDE = -I. -Iupstream/include
UPSTREAM = $(addprefix upstream/src/,exchange_orchestrator.c uhid_transport.c daemon_hid.c daemon_signals.c ctaphid.c mem_util.c pcsc_err.c pcsc_fido_io.c pcsc_log.c daemon_uhid_loop.c daemon_request_handler.c daemon_rate_limit.c daemon_policy.c request_assembly.c apdu.c cbor_util.c)
NATIVE = nfc_auth_lifecycle.c nfc_general_webauthn.c nfc_pin_compat.c nfc_pin_session_policy.c nfc_pin_uv_policy.c nfc_pcsc_bridge.c nfc_apdu.c nfc_socket.c nfc_localhost_policy.c nfc_clientpin_readonly.c nfc_policy_reject_diag.c
SOURCES = bridge_main.c nfc_control.c nfc_runtime_mode.c nfc_auto_trigger.c nfc_recovery_policy.c nfc_auto_window.c nfc_rearm_policy.c nfc_event_proto.c $(NATIVE) $(UPSTREAM)
HEADERS = $(wildcard *.h upstream/include/pcsc_fido/*.h)
.PHONY: all clean test install uninstall
all: hp-elitebook-nfc-bridge
# Header changes must invalidate the build; only C sources are passed as compiler inputs.
hp-elitebook-nfc-bridge: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDE) $(SOURCES) -o $@
clean:
	rm -f hp-elitebook-nfc-bridge

# Deliberately no dependency on `all`: never compile C sources as root.
# Run `make` as an ordinary user before `sudo make install`.
test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q
	bash -n tools/common.sh tools/install.sh tools/uninstall.sh

install:
	@bash tools/install.sh

uninstall:
	@bash tools/uninstall.sh
