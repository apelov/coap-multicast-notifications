#include "sec_debug.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int sec_debug_level = 0;

/* libcoap log handler — routes library output through [DBG] libcoap (§9.3). */
static void sec_libcoap_log_handler(coap_log_t level, const char *message) {
    (void)level;
    /* Strip trailing newline that libcoap adds. */
    size_t len = strlen(message);
    while (len > 0 && (message[len - 1] == '\n' || message[len - 1] == '\r'))
        len--;
    printf("[DBG] libcoap %.*s\n", (int)len, message);
}

void sec_dbg_init(int level) {
    sec_debug_level = level;
    if (level >= 2) {
        coap_set_log_level(COAP_LOG_OSCORE);
    } else if (level >= 1) {
        coap_set_log_level(COAP_LOG_DEBUG);
    }
    if (level >= 1) {
        coap_set_log_handler(sec_libcoap_log_handler);
    }
}

void sec_dbg_bytes(const char *view, const uint8_t *data, size_t len) {
    if (sec_debug_level < 1) return;
    printf("[DBG] %s payload(%zuB)=", view, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf(" \"");
    for (size_t i = 0; i < len; i++) {
        if (isprint(data[i])) printf("%c", data[i]);
        else printf(".");
    }
    printf("\"\n");
}

void sec_dbg_pdu(const char *view, const char *peer, const coap_pdu_t *pdu) {
    if (sec_debug_level < 1) return;

    coap_pdu_code_t code = coap_pdu_get_code(pdu);
    int cl = code >> 5;
    int dt = code & 0x1f;
    const char *type = "NON";
    coap_pdu_type_t ty = coap_pdu_get_type(pdu);
    if (ty == COAP_MESSAGE_CON) type = "CON";
    else if (ty == COAP_MESSAGE_ACK) type = "ACK";
    else if (ty == COAP_MESSAGE_RST) type = "RST";

    coap_bin_const_t tok = coap_pdu_get_token(pdu);

    printf("[DBG] %s %s %s %d.%02d mid=%d tok=", view, peer, type, cl, dt, coap_pdu_get_mid(pdu));
    for (size_t i = 0; i < tok.length; i++) {
        printf("%02x", tok.s[i]);
    }

    printf(" opts=[");
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
    coap_opt_t *opt = coap_option_next(&opt_iter);
    int first = 1;
    while (opt) {
        if (!first) printf(",");
        first = 0;
        printf("%d=", opt_iter.number);
        uint32_t val = coap_opt_length(opt);
        if (val > 0) {
            const uint8_t *ov = coap_opt_value(opt);
            for(uint32_t i=0; i<val; i++) printf("%02x", ov[i]);
        }
        opt = coap_option_next(&opt_iter);
    }
    printf("] ");

    size_t len;
    const uint8_t *data;
    if (coap_get_data(pdu, &len, &data)) {
        printf("payload(%zuB)=", len);
        for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
        printf(" \"");
        for (size_t i = 0; i < len; i++) {
            if (isprint(data[i])) printf("%c", data[i]);
            else printf(".");
        }
        printf("\"\n");
    } else {
        printf("payload(0B)=\n");
    }
}
