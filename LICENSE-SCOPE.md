# Licensing — HP EliteBook X G2i Linux NFC Bridge

**Project identity:** HP EliteBook X G2i Linux NFC Bridge

**Public developer attribution:** MountHex

This archive contains software of **different origins under different
licences**. The top-level MIT `LICENSE` must not be read as relicensing
or replacing original third-party copyright notices.

## Original project-specific contributions: MIT

Copyright (c) 2026 MountHex. The project-original native NFC/UHID
integration, policy/lifecycle components, build and reference deployment
templates in the root and `deploy/` are licensed under **MIT**, to the
extent of the rights held in these original contributions. Read `LICENSE`.
This excludes externally licensed code and any third-party fragments whose
actual origin remains to be determined.

## Incorporated Nero Duality pcsc-fido: Apache-2.0

The `upstream/src/` and `upstream/include/pcsc_fido/` files contain
**pcsc-fido** implementation by Nero Duality, LLC, including downstream
modifications. Preserve the Apache-2.0 SPDX/copyright notices, complete
`upstream/licenses/pcsc-fido-Apache-2.0.txt` and original
`upstream/licenses/pcsc-fido-NOTICE.txt`. See `THIRD-PARTY-NOTICES.md`.

## Separate NXP driver project (not bundled)

The optional HP-specific NXP NFC DKMS driver is independently distributed
and maintained under GPL-2.0-only. No kernel-driver files are included in
this NFC-to-UHID bridge source package. This MIT licence does not apply to
the separate driver or replace its original upstream attributions.

## libfido2 design reference: BSD-2-Clause

`nfc_control.c` and `nfc_apdu.c` reference Yubico **libfido2 1.17.0**
Linux NFC/netlink and APDU wire behaviour as protocol/design models. Yubico libfido2 is
BSD-2-Clause licensed. Its complete 1.17.0 BSD-2-Clause licence is provided
as a precaution at `upstream/licenses/libfido2-BSD-2-Clause.txt`, and its
copyright attribution is retained in `THIRD-PARTY-NOTICES.md`.
No libfido2 source or linked library is distributed here. The design-level
comparison did not demonstrate copied nontrivial implementation, but cannot
prove the historical origin of every line. Any subsequently identified
adapted fragment must retain its original copyright and source-level licence
notice; this project's MIT licence does not supersede Yubico's rights.
