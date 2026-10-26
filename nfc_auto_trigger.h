// SPDX-License-Identifier: MIT
#ifndef NFC_AUTO_TRIGGER_H
#define NFC_AUTO_TRIGGER_H
// 1=FIDO SELECT succeeded; 0=bounded no-target timeout; -1=error;
// -2=SIGINT/SIGTERM. Never emits card identity or sends CTAP commands.
// detect_ms=0 means one unbounded, interruptible idle poll (continuous mode);
// nonzero requests a bounded wait. This does not independently
// verify RF hardware state or guarantee a driver will keep polling forever.
int nfc_auto_trigger_once(unsigned detect_ms);
// After prior session, wait for an operational quiet interval and suppress
// immediate rediscovery of a continuously held key. May block up to detect_ms
// plus bounded local handshakes; NFC I/O loss is not definitive key removal.
int nfc_auto_trigger_guarded(unsigned detect_ms);
#endif
