#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MountHex
# Conventional one-at-a-time systemd Linux fresh installation; NO migration.
set -euo pipefail

source "$(dirname -- "$0")/common.sh"
require_systemd_root
require_programs getent useradd id runuser systemctl udevadm systemd-tmpfiles \
    install sha256sum cmp make sed nologin stdbuf chmod mkdir readlink env test
select_desktop
paths
check_user_unit_parents

[[ -x "$rootdir/hp-elitebook-nfc-bridge" ]] || { echo 'Run make as an ordinary user before sudo make install' >&2; exit 2; }
# `make install` never compiles as root. Refuse a binary stale against C/headers.
if ! make -s -C "$rootdir" -q hp-elitebook-nfc-bridge; then
    echo 'Bridge binary is missing or stale; run make as an ordinary user first' >&2
    exit 2
fi
[[ -d /sys/class/nfc/nfc0 && -e /dev/uhid ]] || { echo 'nfc0 or UHID missing; install compatible driver separately' >&2; exit 2; }
# Do not create half an installation on a minimal systemd host missing
# Polkit, udev or tmpfiles configuration locations.
for config_dir in /etc/systemd/system /etc/polkit-1/rules.d /etc/udev/rules.d /etc/tmpfiles.d; do
    [[ -d "$config_dir" && ! -L "$config_dir" ]] || {
        echo "Required installation configuration directory unavailable: $config_dir" >&2
        exit 2
    }
done
# On hosts with SELinux, require Enforcing and restore labels; do not require
# SELinux on hosts using a different mandatory-access-control system.
check_selinux
# Refuse an existing or concurrently active bridge. This is not an
# automatic upgrade or migration facility.
conflicts=("${targets[@]}" "$userlink" "$recorddir")
# The bridge executable directory must be new, not an adopted old directory.
release_directory_is_unused || {
    echo "Existing or unsafe bridge directory: $libdir" >&2; exit 2;
}
for path in "${conflicts[@]}" \
    /usr/local/libexec/hp-nfc-bridge-*/* \
    /etc/systemd/system/hp-nfc-bridge-*.service \
    /etc/polkit-1/rules.d/*hp-nfc-bridge*.rules \
    /etc/udev/rules.d/*hp-nfc-bridge*.rules \
    /etc/tmpfiles.d/*hp-nfc-bridge*.conf \
    "$home"/.config/systemd/user/hp-nfc-bridge-*.service \
    "$home"/.config/systemd/user/graphical-session.target.wants/hp-nfc-bridge-*.service; do
    if present "$path"; then
        echo "Existing installation artifact: $path" >&2
        echo 'Uninstall the previous bridge separately before a fresh install.' >&2
        exit 2
    fi
done
if bridge_running || systemctl is-active --quiet "$unit" || \
   systemctl is-active --quiet neard.service; then
    echo 'An NFC bridge/poller is still active; installation refused' >&2; exit 2
fi
# Activation uses the systemd graphical-session target. Check for it rather
# than assuming every desktop environment uses that target.
userctl show-environment >/dev/null
userctl is-active --quiet graphical-session.target || {
    echo 'No active systemd graphical-session.target for selected desktop login' >&2
    exit 2
}
# Do the user-home portion before creating the service account or system files.
# This is run as the actual desktop login, never as root in their home.
runuser -u "$desktop" -- mkdir -p -- "$home/.config/systemd/user"
check_user_unit_parents
runuser -u "$desktop" -- test -w "$home/.config/systemd/user" || {
    echo 'Desktop login cannot write its systemd user-unit directory' >&2
    exit 2
}

# Keep the trusted service identity nonroot, nonlogin and separate from DKMS.
if ! getent passwd "$service_user" >/dev/null; then
    [[ ! $(getent group "$service_user") ]] || { echo 'Conflicting service group' >&2; exit 2; }
    nologin_path=$(command -v nologin)
    [[ "$nologin_path" == /* ]] || { echo 'Cannot locate an absolute nologin path' >&2; exit 2; }
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell "$nologin_path" "$service_user"
fi
[[ $(id -gn "$service_user") == "$service_user" ]] || { echo 'Unexpected bridge service group' >&2; exit 2; }
svc_entry=$(getent passwd "$service_user")
IFS=: read -r _ _ svc_uid svc_gid _ svc_home svc_shell <<< "$svc_entry"
[[ "$svc_uid" =~ ^[0-9]+$ && "$svc_uid" -gt 0 && "$svc_uid" != "$uid" && "$svc_home" != "$home" ]] || {
    echo 'Bridge service account must be nonroot and separate from the desktop login' >&2; exit 2;
}
[[ "$svc_shell" == */nologin || "$svc_shell" == */false ]] || { echo 'Bridge service account can log in' >&2; exit 2; }

# Only fixed release-owned files. Do not touch the separate NXP driver.
install -d -m 0755 "$libdir"
install -m 0755 "$rootdir/hp-elitebook-nfc-bridge" "${targets[0]}"
sed "s/__LOGIN_UID__/$uid/g" "$rootdir/deploy/$unit.in" > "${targets[1]}"
chmod 0644 "${targets[1]}"
sed "s/__LOGIN_NAME__/$desktop/g" "$rootdir/deploy/49-hp-elitebook-nfc-bridge.rules.in" > "${targets[2]}"
chmod 0644 "${targets[2]}"
install -m 0644 "$rootdir/deploy/70-hp-elitebook-nfc-bridge-uhid.rules" "${targets[3]}"
install -m 0644 "$rootdir/deploy/90-hp-elitebook-nfc-bridge-uhid.conf" "${targets[4]}"
# Root never writes through potentially user-controlled home symlinks.
check_user_unit_parents
runuser -u "$desktop" -- install -m 0644 "$rootdir/deploy/$userunit" "$userpath"
apply_selinux_contexts "${targets[@]}"
systemctl daemon-reload
udevadm control --reload
systemd-tmpfiles --create "${targets[4]}"

# Receipt permits uninstall of this exact version only (not an upgrade).
install -d -m 0700 "$recorddir"
printf '%s:%s\n' "$desktop" "$uid" > "$recorddir/desktop"
receipt_hashes > "$recorddir/files.sha256"
chmod 0600 "$recorddir/desktop" "$recorddir/files.sha256"
userctl daemon-reload
userctl enable --now "$userunit"
echo 'Installation complete.'
