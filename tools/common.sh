#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MountHex
# Shared, fixed-name helpers for systemd-based Linux source installation.
set -euo pipefail

unit=hp-elitebook-nfc-bridge.service
userunit=hp-elitebook-nfc-bridge-session.service
service_user=hp-nfc-bridge
libdir=/usr/local/libexec/hp-elitebook-nfc-bridge
recorddir=/var/lib/hp-elitebook-nfc-bridge
rootdir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

require_systemd_root() {
    (( EUID == 0 )) || { echo 'Run using sudo, from the reviewed source tree' >&2; exit 2; }
    [[ -d /run/systemd/system ]] || {
        echo 'A running systemd system manager is required' >&2; exit 2;
    }
}

# SELinux may be absent (e.g. on a distribution using AppArmor).
# When it is present, do not silently relax its Enforcing policy.
check_selinux() {
    local path=${1:-/sys/fs/selinux/enforce} state
    if [[ -e "$path" ]]; then
        [[ -r "$path" ]] || { echo 'Cannot read SELinux state' >&2; return 2; }
        state=$(<"$path")
        [[ "$state" == 1 ]] || { echo 'SELinux is present but not Enforcing' >&2; return 2; }
        require_programs restorecon
    fi
}

apply_selinux_contexts() {
    [[ -e /sys/fs/selinux/enforce ]] || return 0
    restorecon -F "$@"
}

# Fail before file creation if required system tools are missing.
require_programs() {
    local program
    for program in "$@"; do
        command -v "$program" >/dev/null 2>&1 || {
            printf 'Missing required command: %s\n' "$program" >&2
            exit 2
        }
    done
}

select_desktop() {
    desktop=${DESKTOP_USER:-${SUDO_USER:-}}
    [[ "$desktop" =~ ^[a-z_][a-z0-9_-]*$ && "$desktop" != root ]] || {
        echo 'Specify a valid desktop login via DESKTOP_USER or sudo' >&2; exit 2;
    }
    local entry
    entry=$(getent passwd "$desktop") || { echo 'Desktop login account not found' >&2; exit 2; }
    IFS=: read -r _ _ uid gid _ home shell <<< "$entry"
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$uid" -ge 1000 && "$home" == /* && "$home" != / ]] || {
        echo 'Desktop login account is not eligible' >&2; exit 2;
    }
    [[ -d "$home" && ! -L "$home" ]] || { echo 'Unsafe or missing home directory' >&2; exit 2; }
    userpath="$home/.config/systemd/user/$userunit"
    userlink="$home/.config/systemd/user/graphical-session.target.wants/$userunit"
}

paths() {
    targets=(
        "$libdir/hp-elitebook-nfc-bridge"
        "/etc/systemd/system/$unit"
        /etc/polkit-1/rules.d/49-hp-elitebook-nfc-bridge.rules
        /etc/udev/rules.d/70-hp-elitebook-nfc-bridge-uhid.rules
        /etc/tmpfiles.d/90-hp-elitebook-nfc-bridge-uhid.conf
        "$userpath"
    )
}

present() { [[ -e "$1" || -L "$1" ]]; }

# User-unit paths live under the desktop user's control. Refuse a symlink
# in their parent chain; never traverse an alias into unrelated locations.
check_user_unit_parents() {
    local part
    for part in "$home/.config" "$home/.config/systemd" \
                "$home/.config/systemd/user" \
                "$home/.config/systemd/user/graphical-session.target.wants"; do
        if present "$part" && [[ ! -d "$part" || -L "$part" ]]; then
            echo "Unsafe user unit parent: $part" >&2
            return 2
        fi
    done
}

# A fresh installation owns this entire fixed directory. If it is present,
# do not overwrite, follow a symlink, or adopt unknown prior contents.
release_directory_is_unused() { ! present "$libdir"; }

# The only directory contents the release knows how to remove. This check
# happens before stopping services or removing any files.
release_directories_are_exact() (
    [[ -d "$libdir" && ! -L "$libdir" && -d "$recorddir" && ! -L "$recorddir" ]] || return 1
    shopt -s nullglob dotglob
    local -a installed=("$libdir"/*) receipts=("$recorddir"/*)
    [[ ${#installed[@]} -eq 1 && "${installed[0]}" == "${targets[0]}" ]] &&
    [[ ${#receipts[@]} -eq 2 ]] &&
    [[ "${receipts[0]}" == "$recorddir/desktop" ]] &&
    [[ "${receipts[1]}" == "$recorddir/files.sha256" ]]
)

userctl() {
    [[ -d "/run/user/$uid" && -S "/run/user/$uid/bus" ]] || {
        echo 'Desktop systemd user bus unavailable: stop and inspect' >&2; exit 2;
    }
    runuser -u "$desktop" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        systemctl --user "$@"
}

bridge_running() {
    local process exe
    for process in /proc/[0-9]*; do
        exe=$(readlink "$process/exe" 2>/dev/null) || continue
        case "$exe" in "$libdir"/*|/usr/local/libexec/hp-nfc-bridge-*/*) return 0 ;; esac
    done
    return 1
}

receipt_hashes() {
    sha256sum "${targets[@]}"
}

# Compare a receipt only against the fixed destination list, not parsed paths
# from a receipt. This also works for valid paths containing whitespace.
receipt_matches() {
    [[ -f "$recorddir/files.sha256" && ! -L "$recorddir/files.sha256" ]] &&
        cmp -s -- "$recorddir/files.sha256" <(receipt_hashes)
}
