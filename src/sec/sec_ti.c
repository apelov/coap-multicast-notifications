#include "sec_ti.h"
#include <coap3/coap_internal.h>
#include <string.h>

size_t sec_ti_export(const coap_pdu_t *pdu, uint8_t *out, size_t max) {
    coap_opt_iterator_t oi;
    coap_opt_t *o;
    uint16_t prev = 0;
    size_t n = 1, w, dlen;
    const uint8_t *data;

    if (!pdu || !out || max < 1) return 0;
    out[0] = (uint8_t)coap_pdu_get_code(pdu);
    coap_option_iterator_init(pdu, &oi, COAP_OPT_ALL);
    while ((o = coap_option_next(&oi))) {
        w = coap_opt_encode(out + n, max - n, oi.number - prev, coap_opt_value(o), coap_opt_length(o));
        if (!w) return 0;
        n += w;
        prev = oi.number;
    }
    if (coap_get_data(pdu, &dlen, &data) && dlen) {
        if (n + 1 + dlen > max) return 0;
        out[n++] = COAP_PAYLOAD_START;
        memcpy(out + n, data, dlen);
        n += dlen;
    }
    return n;
}

int sec_tuple_from_option(const uint8_t *opt, size_t len, sec_tuple_t *tuple) {
    cose_encrypt0_t c[1];
    if (!opt || !len || !tuple) return 0;
    cose_encrypt0_init(c);
    if (!oscore_decode_option_value(opt, len, c) || !c->group_flag ||
        !c->key_id.length || !c->partial_iv.length || !c->kid_context.length ||
        !c->key_id.s || !c->partial_iv.s || !c->kid_context.s ||
        c->key_id.length > sizeof(tuple->kid) ||
        c->partial_iv.length > sizeof(tuple->piv) ||
        c->kid_context.length > sizeof(tuple->kid_ctx))
        return 0;

    memset(tuple, 0, sizeof(*tuple));
    memcpy(tuple->kid, c->key_id.s, c->key_id.length);
    tuple->kid_len = c->key_id.length;

    memcpy(tuple->piv, c->partial_iv.s, c->partial_iv.length);
    tuple->piv_len = c->partial_iv.length;

    memcpy(tuple->kid_ctx, c->kid_context.s, c->kid_context.length);
    tuple->kid_ctx_len = c->kid_context.length;

    return 1;
}

int sec_ti_import(const uint8_t *ti, size_t n, const uint8_t *tok, size_t tkl, int is_request, unsigned compat, coap_pdu_t **out) {
    coap_pdu_t *pdu;
    coap_opt_filter_t bad;

    if (!out) return 0;
    *out = NULL;
    if (!ti || n < 1 || tkl > 8 || (tkl && !tok)) return 0;

    uint8_t code = ti[0];
    const uint8_t *start = ti + 1;
    size_t remain = n - 1;

    /* compat: java client might send UDP header, check if it's UDP format */
    if (compat && (ti[0] & 0xc0) == 0x40) {
        if (n < 4 + tkl || (ti[0] >> 6) != 1 || (ti[0] & 0x0f) > 8 ||
            (size_t)(ti[0] & 0x0f) != tkl ||
            (ti[0] & 0x30) >= 0x20 || memcmp(ti + 4, tok, tkl) != 0) {
            return 0;
        }
        code = ti[1];
        start = ti + 4 + tkl;
        remain = n - (4 + tkl);
    }

    if (is_request && code != COAP_REQUEST_CODE_FETCH) {
        return 0;
    }

    pdu = coap_pdu_init(COAP_MESSAGE_NON, code, 0, tkl + remain + 16);
    if (!pdu || !coap_add_token(pdu, tkl, tok) ||
        !coap_pdu_check_resize(pdu, pdu->e_token_length + remain)) {
        coap_delete_pdu(pdu);
        return 0;
    }
    if (remain) {
        memcpy(pdu->token + pdu->e_token_length, start, remain);
    }
    pdu->used_size = pdu->e_token_length + remain;

    if (!coap_pdu_parse_opt(pdu, &bad)) {
        coap_delete_pdu(pdu);
        return 0;
    }

    /* Policy from design 10.1: accept only Uri-Host (3), Observe (6), Uri-Port (7) and OSCORE (9) for requests */
    if (is_request) {
        coap_opt_iterator_t oi;
        coap_opt_t *opt;
        coap_option_iterator_init(pdu, &oi, COAP_OPT_ALL);
        while ((opt = coap_option_next(&oi))) {
            if (oi.number != COAP_OPTION_URI_HOST &&
                oi.number != COAP_OPTION_OBSERVE &&
                oi.number != COAP_OPTION_URI_PORT &&
                oi.number != COAP_OPTION_OSCORE) {
                coap_delete_pdu(pdu);
                return 0;
            }
        }
    }

    *out = pdu;
    return 1;
}
