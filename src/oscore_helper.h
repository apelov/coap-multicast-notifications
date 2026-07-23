#ifndef OSCORE_HELPER_H
#define OSCORE_HELPER_H

#include <coap3/coap.h>

/**
 * Creates a standard OSCORE configuration object for either server or client.
 * 
 * @param is_server 1 if setting up server context, 0 for client context.
 * @return A pointer to the created coap_oscore_conf_t configuration, or NULL on failure.
 */
coap_oscore_conf_t *setup_oscore_conf(int is_server);

#endif /* OSCORE_HELPER_H */
