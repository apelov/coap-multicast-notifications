#ifndef SEC_TI_H
#define SEC_TI_H

#include <coap3/coap.h>
#include <stdint.h>
#include <stddef.h>
#include "sec_state.h"

size_t sec_ti_export(const coap_pdu_t *pdu, uint8_t *out, size_t max);
int sec_tuple_from_option(const uint8_t *opt, size_t len, sec_tuple_t *tuple);
int sec_ti_import(const uint8_t *ti, size_t n, const uint8_t *tok, size_t tkl, int is_request, unsigned compat, coap_pdu_t **out);


#endif
