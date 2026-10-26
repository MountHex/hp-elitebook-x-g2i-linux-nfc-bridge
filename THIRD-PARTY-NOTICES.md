# Third-party attribution and modification notices

## pcsc-fido (Nero Duality, LLC)

**Project:** https://github.com/neroduality/pcsc-fido

**Copyright:** Copyright (C) 2026 Nero Duality, LLC.

**Licence:** Apache License, Version 2.0 (Apache-2.0).

The `upstream/src/` and `upstream/include/pcsc_fido/` files are redistributed
from or derived from **pcsc-fido**, used here to support a UHID/FIDO bridge.
The original `upstream/licenses/pcsc-fido-Apache-2.0.txt` and
`upstream/licenses/pcsc-fido-NOTICE.txt` are distributed verbatim.
Their upstream attribution is retained even when downstream source has changed.

**Downstream modifications:** Selected Nero Duality `pcsc-fido` files have
been adapted for the native NFC bridge, including virtual HID identity, service
integration, browser-request handling, diagnostics, and removal of an unused
alternative runtime. The original copyright, full Apache-2.0 licence and
original NOTICE are retained; these files do **not** become MIT-only code.
Every locally modified inherited C/header file bears a prominent source-level
modification notice in addition to its original upstream header.

This project is an independent adaptation, not a Nero Duality release or
endorsement, and it is not an official HP release.

### Downstream-modified inherited files

The following ten files carry changes relative to a locally preserved
source baseline. The exact originating upstream Git revision is not known.

- `upstream/include/pcsc_fido/browser_daemon.h`
- `upstream/include/pcsc_fido/daemon_policy.h`
- `upstream/include/pcsc_fido/daemon_signals.h`
- `upstream/include/pcsc_fido/daemon_uhid_loop.h`
- `upstream/include/pcsc_fido/pcsc_bridge.h`
- `upstream/include/pcsc_fido/pcsc_err.h`
- `upstream/src/daemon_signals.c`
- `upstream/src/exchange_orchestrator.c`
- `upstream/src/pcsc_log.c`
- `upstream/src/uhid_transport.c`

### Other incorporated and adapted modules

These seven modules were incorporated subsequently and bear downstream
modification notices. Their precise original upstream revision is not known.

- `upstream/src/apdu.c`
- `upstream/src/cbor_util.c`
- `upstream/src/daemon_policy.c`
- `upstream/src/daemon_rate_limit.c`
- `upstream/src/daemon_request_handler.c`
- `upstream/src/daemon_uhid_loop.c`
- `upstream/src/request_assembly.c`

Original upstream copyright and licence headers are retained across the
incorporated sources. The exact upstream Git revision remains unverified;
see `UPSTREAM-PROVENANCE.md`.

## Project-original native NFC and service code

**HP EliteBook X G2i Linux NFC Bridge — MountHex.** Original project-specific
contributions are offered under MIT, as scoped in `LICENSE-SCOPE.md`. This attribution does not cover or override Nero Duality's Apache-licensed
files.

## libfido2 design reference (Yubico)

`nfc_control.c` and `nfc_apdu.c` document modelling Linux NFC netlink and
ISO 7816/APDU wire behaviour on Yubico
**libfido2 1.17.0**, especially `src/netlink.c`, `src/nfc_linux.c`
and `src/nfc.c`.
Copyright (c) 2018–2026 Yubico AB. Project: https://github.com/Yubico/libfido2 — **BSD-2-Clause**. No libfido2
source or library is included or linked in this source archive. The complete
BSD-2-Clause licence is additionally included at
`upstream/licenses/libfido2-BSD-2-Clause.txt` as a conservative reference
notice. Comparing the NFC code showed distinct internal designs and did not
establish copied copyrightable implementation; this review cannot prove
historical independent authorship of every line.

## Separate Linux NXP driver (not distributed here)

Some HP systems require the independently maintained, kernel-derived
GPL-2.0-only NXP NFC DKMS driver. It is **not** present in this package;
its source, licensing, build and Secure Boot signing belong to its own
repository. No module, signing key or driver installer is bundled here.
