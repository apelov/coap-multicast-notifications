#ifndef SEC_GROUP_H
#define SEC_GROUP_H

#include <coap3/coap.h>
#include "sec_state.h"
typedef struct oscore_ctx_t oscore_ctx_t;

typedef struct sec_grp_s {
    coap_context_t *ctx;
} sec_grp_t;

int sec_phantom_protect(sec_grp_t *grp, const char *uri_path, const uint8_t *T, size_t tkl, uint8_t *ph_req, size_t *ph_len, sec_tuple_t *tuple);
int sec_phantom_verify(sec_grp_t *grp, const uint8_t *ph_req, size_t ph_len, const uint8_t *T, size_t tkl, const char *expect_path, unsigned compat, sec_tuple_t *out);



size_t sec_build_e_aad(oscore_ctx_t *ctx, const sec_tuple_t *req, const uint8_t *opt, size_t optlen, const coap_crypto_cred_t *sender, uint8_t *out, size_t max);

int sec_notif_protect(sec_grp_t *grp, const sec_tuple_t *req, const uint8_t *T, size_t tkl, uint32_t observe, const uint8_t *val, size_t vallen, unsigned max_age, coap_mid_t mid, uint8_t *udp, size_t *udp_len, uint8_t *ti, size_t *ti_len, uint64_t *piv);

int sec_notif_verify(sec_grp_t *grp, const sec_tuple_t *req, coap_pdu_t *pdu, unsigned compat, uint64_t *piv, uint8_t *pt, size_t *ptlen);

int sec_mcast_send(coap_context_t *uc_ctx, const char *grp, uint16_t port, const uint8_t *udp, size_t len);
#endif
