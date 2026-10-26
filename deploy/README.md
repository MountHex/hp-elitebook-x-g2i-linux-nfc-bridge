# Service configuration

These are templates installed automatically by `sudo make install`.
The system service runs under the restricted `hp-nfc-bridge` account and
is activated by the desktop user's `graphical-session.target` service.
Polkit restricts start/stop permission to that user. udev and tmpfiles
restrict `/dev/uhid` to `root:hp-nfc-bridge` (`0660`).

See the main `README.md` for installation, use and removal.
The NXP DKMS driver is managed separately.
