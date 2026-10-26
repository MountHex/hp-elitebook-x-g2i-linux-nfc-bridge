# HP EliteBook X G2i Linux NFC Bridge

**MountHex** · Independent community project; not affiliated with HP, NXP, Nero Duality or Yubico.

A source-built Linux bridge that exposes a compatible NFC FIDO2 security key to
browsers as a temporary virtual HID authenticator. It uses the native Linux NFC
interface (`nfc0`) and `/dev/uhid`, not a PC/SC reader.

The bridge supports browser WebAuthn authentication and registration, including
PIN/UV authentication when required. Authenticator PIN changes, resets,
credential management and non-FIDO applications are not supported. The virtual
HID device is removed after each authentication activity window.

## Requirements and compatibility

**Hardware tested:** HP EliteBook X G2i, Fedora 45 GNOME, integrated NXP NFC
controller, NFC YubiKey, Helium browser and GitHub WebAuthn. Successful sign-in
has been confirmed on this configuration. Hardware validation of the *exact*
final release build is performed separately from source compilation tests.

**Other systems:** The source installer targets systemd-based Linux
installations with system and user service managers, an active
`graphical-session.target`, Polkit JavaScript rules, udev and tmpfiles.
Other distributions, desktops and native NFC controllers are compatibility
targets, not independently verified configurations.

The system must already expose a working `nfc0` controller and `/dev/uhid`.
An HP-specific NXP DKMS driver, if needed, must be installed separately. This
project does **not** contain or manage kernel drivers, DKMS or Secure Boot keys.

Build tools: Make, a C23-capable compiler (for example GCC 13+), Linux
userspace development headers, Python 3 and Bash. The installer also uses
standard Linux systemd, account-management, SELinux (where present), Polkit,
udev and tmpfiles utilities. Dependencies are not installed automatically;
package names vary by distribution.

## Install from source

Inspect and verify the source before running administrator commands.
From the extracted source directory, in a supported graphical session:

```bash
make
make test
sudo make install
```

`make` compiles the bridge as a normal user. `make test` runs offline tests
without accessing NFC hardware. The installer adds the bridge executable,
restricted service identity if needed, systemd services, Polkit, udev and
tmpfiles rules, and enables graphical-session activation.

Only **one bridge** may be installed. To replace a release, uninstall it first
using its original source directory. There is no in-place upgrade, automatic
migration or rollback. Keep the source directory for that release's
uninstaller.

## Verify and use

```bash
systemctl show hp-elitebook-nfc-bridge.service \
  -p ActiveState -p SubState -p MainPID -p User -p Group -p NRestarts
systemctl --user is-enabled hp-elitebook-nfc-bridge-session.service
stat -c '%a %U:%G' /dev/uhid
sudo journalctl -u hp-elitebook-nfc-bridge.service -n 40 --no-pager
```

Use a browser's normal WebAuthn flow and present a compatible NFC security key.
Confirm sign-in completes before treating an installation as working. The
bridge waits for another presentation after its quiet/rearm interval.

Do not operate another NFC reader poller against the same controller. If the
reader or driver hangs, do not repeatedly restart the bridge or unbind/rebind
the kernel driver.

## Uninstall

From the **same version's source directory** used for installation:

```bash
sudo make uninstall
```

The uninstaller disables activation, stops the service and removes its
recorded executable and configuration files. It leaves the service account,
NFC driver, other system configuration and user data in place. Unexpected
changes to installed files cause removal to stop for manual inspection.

A failed install or uninstall can leave partially installed files. Check the
reported failure and affected paths before attempting another operation.

## Security

The bridge runs as a dedicated non-login `hp-nfc-bridge` user with only
`CAP_NET_ADMIN` available to its process. Polkit limits start/stop of its
system service to the selected graphical user. `/dev/uhid` is restricted to
`root:hp-nfc-bridge` with mode `0660`. On hosts with SELinux, installation
requires Enforcing and restores file contexts; no change is made to Secure
Boot or the NFC driver.

## Source layout and licences

- `Makefile`, `tools/`: build, installation and uninstallation.
- `deploy/`: systemd, Polkit, udev and tmpfiles templates.
- Root `.c`/`.h` files: native NFC interface and application policy.
- `upstream/`: incorporated Nero Duality **pcsc-fido** components.
- `tests/`: offline source-interface checks.

Project-original contributions are under MIT (`LICENSE` and
`LICENSE-SCOPE.md`). Incorporated `pcsc-fido` material remains under
Apache-2.0 with its copyright and NOTICE preserved. Yubico libfido2 was a
BSD-2-Clause design reference, not a bundled library. See
`THIRD-PARTY-NOTICES.md` and `UPSTREAM-PROVENANCE.md` for origins,
modifications and the available source-provenance evidence.
