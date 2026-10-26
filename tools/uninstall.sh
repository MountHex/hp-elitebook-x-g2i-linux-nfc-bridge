#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MountHex
# Remove only this recorded release; never remove the separate NXP driver.
set -euo pipefail

source "$(dirname -- "$0")/common.sh"
require_systemd_root
require_programs getent runuser systemctl udevadm sha256sum cmp rm rmdir cat readlink env
select_desktop
paths
check_user_unit_parents
[[ -d "$recorddir" && ! -L "$recorddir" && -f "$recorddir/desktop" && ! -L "$recorddir/desktop" && -f "$recorddir/files.sha256" && ! -L "$recorddir/files.sha256" ]] || {
    echo 'Installation receipt unavailable; stop for manual review' >&2; exit 2;
}
[[ $(cat "$recorddir/desktop") == "$desktop:$uid" ]] || { echo 'Installation account mismatch' >&2; exit 2; }
# Reject missing/changed files; never use receipt data to select deletion paths.
for path in "${targets[@]}"; do
    [[ -f "$path" && ! -L "$path" ]] || { echo "Missing or unsafe release file: $path" >&2; exit 2; }
done
receipt_matches || { echo 'Installed files or receipt differ from this release: manual review required' >&2; exit 2; }
# No unknown files in directories we intend to remove. Check before stopping
# services or deleting the receipt, so an unexpected file leaves state intact.
release_directories_are_exact || {
    echo 'Unexpected files in release directories; stop for manual review' >&2; exit 2;
}
# Disable desktop session activation, then stop this exact system service, then check no process remains.
userctl disable --now "$userunit"
systemctl stop "$unit"
if systemctl is-active --quiet "$unit" || bridge_running || present "$userlink"; then
    echo 'Bridge still running or activation link present: STOP, do not remove files' >&2; exit 2
fi
# Re-verify after service changes, before deleting release-owned files.
receipt_matches || { echo 'Installed files changed during stop; STOP' >&2; exit 2; }
# The user-controlled graphical-session file must never be deleted as root.
runuser -u "$desktop" -- rm -- "$userpath"
rm -- "${targets[@]:0:5}"
rm -- "$recorddir/files.sha256" "$recorddir/desktop"
rmdir -- "$recorddir" "$libdir"
systemctl daemon-reload
udevadm control --reload
userctl daemon-reload
echo 'Uninstallation complete.'
