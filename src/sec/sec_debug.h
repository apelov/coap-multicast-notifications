#ifndef SEC_DEBUG_H
#define SEC_DEBUG_H

#include <coap3/coap.h>
#include <stdint.h>

void sec_dbg_pdu(const char *view, const char *peer, const coap_pdu_t *pdu);
void sec_dbg_bytes(const char *view, const uint8_t *data, size_t len);

/* Call after coap_startup() to set libcoap log level and install the
 * [DBG] libcoap routing handler per design §9.3.  -d 1 → COAP_LOG_DEBUG;
 * -d 2 → COAP_LOG_OSCORE (keys, nonces, AAD as the fork logs them). */
void sec_dbg_init(int level);

extern int sec_debug_level;

#endif
