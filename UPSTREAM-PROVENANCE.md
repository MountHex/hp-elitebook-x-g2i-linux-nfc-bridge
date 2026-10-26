# External source provenance — current evidence and limitations

This record covers external sources present in or referred to by this source
distribution. **It is not a claim of full upstream commit verification.**

## pcsc-fido — Nero Duality, LLC — Apache-2.0

Source repository: https://github.com/neroduality/pcsc-fido

The incorporated code originates from third-party `pcsc-fido` material, with
downstream modifications and later-incorporated upstream modules.

**Source integration:** Selected inherited files have been modified or
incorporated and adapted for native NFC. Each known changed or adapted file
bears a prominent downstream modification notice. A private comparison to
a locally preserved downstream source baseline supports the local modification
inventory but does not establish the exact originating upstream commit.

The upstream licence and NOTICE remain in this distribution. The exact
original upstream Git commit has not been independently identified, so no
commit identity is asserted. A pinned upstream revision would improve
traceability but is not itself a requirement of Apache-2.0 redistribution;
preserving original attribution, licence/NOTICE and modification notices
remains mandatory.

## Yubico libfido2 1.17.0 — BSD-2-Clause (reference only)

Source references:
- https://github.com/Yubico/libfido2/blob/1.17.0/src/netlink.c
- https://github.com/Yubico/libfido2/blob/1.17.0/src/nfc_linux.c
- https://github.com/Yubico/libfido2/blob/1.17.0/src/nfc.c
- https://github.com/Yubico/libfido2/blob/1.17.0/LICENSE

`nfc_control.c` and `nfc_apdu.c` state the Linux NFC Netlink and APDU
wire sequences were modelled on these reference implementations. The native adapter uses its own fixed-size netlink
message representation and event loop, whereas libfido2's original
`netlink.c` uses its own dynamically allocated message abstraction; and
libfido2's `nfc_linux.c` manages a libfido2 NFC device abstraction and udev
enumeration absent from the native module. The project's `nfc_apdu.c` uses
its own cancellable and deadline-bounded I/O callbacks; libfido2's `nfc.c`
uses libfido2 device I/O and ISO 7816 allocation routines. The shared
FIDO NFC AID, APDU instructions, response status words and chaining sequence
are protocol elements, not by themselves evidence of a code copy.

This supports a separate local implementation at the architecture level; the
review identified no obvious nontrivial copied implementation, but is **not a
forensic proof of independent authorship of every line**. No libfido2 source or
library is bundled or linked. For conservative attribution, the original
libfido2 1.17.0 BSD-2-Clause licence is included at
`upstream/licenses/libfido2-BSD-2-Clause.txt`. If a copyrightable adapted code
fragment is established later, preserve its original Yubico attribution and
source-level BSD-2-Clause notice, not an MIT substitution.

## Optional NXP Linux driver — separate project

The HP-specific GPL-2.0-only NFC DKMS driver is not redistributed in this
bridge source tree. Its upstream provenance and patch history must be
documented in the separate driver repository.

## Scope and limitations

The downstream virtual HID identity differs from upstream `pcsc-fido`;
Apache-2.0 continues to apply to the incorporated upstream source. The
exact upstream revision remains an acknowledged traceability limitation.
This record does not certify hardware compatibility or the separate NXP
driver project.
