// SPDX-License-Identifier: MIT
#include "nfc_clientpin_readonly.h"
#include <string.h>

bool nfc_clientpin_readonly_allowed(const uint8_t *request, size_t len) {
    /* Canonical, exact binary requests. A syntactically different encoding
     * fails closed even if it could decode to an equivalent CBOR object. */
    static const uint8_t retries_with_protocol[] = {
        0x06u,0xa2u,0x01u,0x01u,0x02u,0x01u
    };
    static const uint8_t retries_without_protocol[] = {
        0x06u,0xa1u,0x02u,0x01u
    };
    static const uint8_t agreement[] = {
        0x06u,0xa2u,0x01u,0x01u,0x02u,0x02u
    };
    if (!request) return false;
    return (len==sizeof(retries_with_protocol) &&
            memcmp(request,retries_with_protocol,len)==0) ||
           (len==sizeof(retries_without_protocol) &&
            memcmp(request,retries_without_protocol,len)==0) ||
           (len==sizeof(agreement) &&
            memcmp(request,agreement,len)==0);
}
