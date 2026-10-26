# HP EliteBook X G2i Linux NFC Bridge

Use the built-in NFC reader on an HP EliteBook X G2i with an NFC-enabled FIDO2 security key for browser sign-in on Linux.

Linux can communicate with the laptop's NFC reader, but browsers don't normally see it as a FIDO2 authenticator. This project bridges that gap: it talks to the reader through Linux's native NFC interface (`nfc0`) and presents the security key to the browser as a temporary virtual HID device using `/dev/uhid`.

It is a userspace bridge, **not an NFC kernel driver** or a PC/SC reader.

## Why this bridge exists

Many existing NFC-to-FIDO2 bridges communicate with NFC readers through **PC/SC** (often via `pcscd`). The HP EliteBook X G2i's built-in NXP reader is instead exposed through **Linux's native NFC subsystem** as `nfc0`, rather than as a PC/SC reader. That means PC/SC-based bridges cannot directly use the laptop's built-in reader.

This project was built to bridge that gap: it communicates with the native Linux NFC interface and makes an NFC security key available to browsers through a virtual HID device, allowing FIDO2/WebAuthn sign-in without an external PC/SC reader.

## Before you start: install the NFC driver first

**The tested HP EliteBook X G2i needs an HP-specific NXP NFC driver.** Install the modified [`nxp-nci_i2c` DKMS driver](https://github.com/MountHex/hp-elitebook-x-g2i-nxp-nci-dkms) and confirm that the built-in NFC reader works **before** installing this bridge. The standard upstream driver uses a different GPIO mapping on this laptop.

The driver repository provides the **already-modified source** and [Fedora DKMS installation instructions](https://github.com/MountHex/hp-elitebook-x-g2i-nxp-nci-dkms#installing-on-fedora-new-installation-only). You do not need to patch the source yourself. The driver is a separate project: this bridge does not install or manage kernel modules, DKMS packages or Secure Boot signing keys. If your NFC reader already works, don't replace its driver just to install this bridge.

The installation order is:

1. Follow the driver repository's DKMS installation instructions for your running kernel. With Secure Boot enabled, the module must be signed using a key enrolled on your machine.
2. Check that the patched driver is installed and that the native NFC reader actually works.
3. Build and install this bridge.

These read-only commands help check the driver before proceeding:

```bash
dkms status
modinfo -n nxp_nci_i2c
ls -ld /sys/class/nfc/nfc0
```

On the tested system, `modinfo -n` resolves to the DKMS module under `/lib/modules/.../extra/`. **Seeing `nfc0` alone does not prove the reader is healthy.** The bridge cannot fix a missing or malfunctioning kernel driver.

## Tested setup and requirements

The bridge has been tested on:

- **Laptop:** HP EliteBook X G2i with its integrated NXP NFC controller
- **Linux:** Fedora 45 with GNOME
- **Security key:** NFC-capable YubiKey
- **Browser authentication:** Helium and GitHub WebAuthn sign-in, including the PIN/UV path
- **Security configuration:** Secure Boot enabled and SELinux Enforcing

Other Linux laptops with a working native NFC controller may be adaptable, but they have **not** been tested or verified here. Likewise, Fedora/GNOME is the verified environment; other Linux distributions and desktop sessions are not currently supported by test evidence.

The installer expects a systemd-based Linux desktop with a running `graphical-session.target`, system and user service managers, Polkit JavaScript rules, udev and tmpfiles. You also need a working `nfc0` reader, `/dev/uhid`, Make, Python 3, Bash, a C23-capable compiler (such as GCC 13 or later) and Linux development headers. Dependencies are not installed automatically.

## Build and install

Once the modified driver is installed and the reader is working, run these commands from this project's source directory:

```bash
make
make test
sudo make install
```

Build as your **normal user**, not root. `make test` runs offline checks; it does not access the NFC hardware. The installer then sets up the bridge executable, a restricted service account, systemd activation and the required Polkit, udev and tmpfiles configuration.

There is **no in-place upgrade**. If you're replacing an earlier release, uninstall it using that release's original source directory before installing the new one. Keep each installed version's source directory so its uninstaller can check and remove the right files.

## Using the bridge

Sign in to a website that supports security keys, choose its usual security-key/WebAuthn option, and hold your NFC key against the laptop's reader when prompted. The bridge presents the key to the browser during authentication and removes the virtual HID device afterwards. It automatically becomes ready for the next attempt after a quiet interval.

To inspect the service and recent logs:

```bash
systemctl show hp-elitebook-nfc-bridge.service \
  -p ActiveState -p SubState -p MainPID -p User -p Group -p NRestarts
systemctl --user is-enabled hp-elitebook-nfc-bridge-session.service
stat -c '%a %U:%G' /dev/uhid
sudo journalctl -u hp-elitebook-nfc-bridge.service -n 40 --no-pager
```

The bridge is for browser FIDO2/WebAuthn use. It does **not** provide general PC/SC applications, security-key PIN changes or resets, or credential management.

**Avoid running another NFC poller against the same controller.** If the reader stops responding, check the logs rather than repeatedly restarting services, reloading the driver or unbinding the NFC hardware. Such recovery attempts can make a hardware/driver fault worse.

## Uninstall

From the **original source directory for the installed version**:

```bash
sudo make uninstall
```

This disables the bridge's session activation, stops its service and removes the files recorded for that installation. It does **not** remove the separately installed NFC DKMS driver, the service account or unrelated system configuration. If installed files have changed unexpectedly, the uninstaller stops rather than guessing what to delete.

## Security and source licences

The bridge runs as a dedicated non-login `hp-nfc-bridge` account, with only the network administration capability needed for the Linux NFC interface. Polkit limits service start/stop access to the selected desktop user, and `/dev/uhid` is restricted to `root:hp-nfc-bridge` (`0660`). On the tested Fedora system, SELinux remains Enforcing and Secure Boot stays enabled.

MountHex's original project code is MIT-licensed. The included components derived from **Nero Duality's `pcsc-fido`** retain their Apache-2.0 licence and notices. Yubico's libfido2 was used as a design reference and is not bundled. See `LICENSE`, `LICENSE-SCOPE.md`, `THIRD-PARTY-NOTICES.md` and `UPSTREAM-PROVENANCE.md` for details.

This is an independent community project, not affiliated with HP, NXP, Nero Duality or Yubico.
