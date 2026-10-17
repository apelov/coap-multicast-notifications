#include "tap.h"
#include "../../src/sec/sec_group.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap_internal.h>
#include <string.h>

#define GM_CCS  "a501781a636f6170733a2f2f6d79736974652e6578616d706c652e636f6d026c67726f75706d616e6167657203781a636f6170733a2f2f646f6d61696e2e6578616d706c652e6f7267041aab9b154f08a101a4010103272006215820cde3efd3bc3f99c9c9ee210415c6cba55061b5046e963b8a58c9143a61166472"
#define SRV_CCS "a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d026673656e64657203781a636f6170733a2f2f636c69656e742e6578616d706c652e6f7267041a70004b4f08a101a401010327200621582077ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b"
#define AAD_HEAD     "8901840a0a27381a41524100404344616c"
#define AAD_TAIL     "5876" SRV_CCS "587c" GM_CCS
#define EXP_OPTION   "39000344616c52"
#define EXP_AAD_CONF AAD_HEAD "47" EXP_OPTION AAD_TAIL

#define AAD_ALGS  "8901840a0a27381a"
#define EXP_AAD_NOTIF(req_piv_cbor, opt_cbor) \
  AAD_ALGS "4152" req_piv_cbor "40" "4344616c" opt_cbor AAD_TAIL

static size_t unhex(const char *h, uint8_t *b, size_t max) {
    size_t i = 0;
    while (h[i*2] && h[i*2+1] && i < max) {
        sscanf(h + i*2, "%2hhx", &b[i]);
        i++;
    }
    return i;
}

static int eq_hex(const uint8_t *b, size_t n, const char *hex) {
    uint8_t e[1024];
    size_t el = unhex(hex, e, sizeof(e));
    return n == el && memcmp(b, e, n) == 0;
}

int main(void) {
    coap_startup();
    sec_config_t cfg;
    char text[2048];
    if (sec_config_load("docs/secure/examples/section10/server.conf", &cfg) < 0 ||
        sec_conf_group_text(&cfg, text, sizeof(text)) < 0) return 1;
    coap_context_t *ctx = coap_new_context(NULL);
    coap_str_const_t config = { strlen(text), (const uint8_t *)text };
    coap_oscore_conf_t *oc = coap_new_oscore_conf(config, NULL, NULL, cfg.group_start_sn);
    coap_context_oscore_server(ctx, oc);
    oscore_ctx_t *osc = ctx->p_osc_ctx;

    coap_set_log_level(COAP_LOG_ERR);

    sec_tuple_t req;
    req.kid_len = 1; req.kid[0] = 0x52;
    req.piv_len = 1; req.piv[0] = 0x00;
    req.kid_ctx_len = 3; unhex("44616c", req.kid_ctx, 3);

    uint8_t out[1024];
    uint8_t opt[256];
    size_t opt_len = unhex(EXP_OPTION, opt, sizeof(opt));
    size_t n = sec_build_e_aad(osc, &req, opt, opt_len, osc->sender_context->sender_cred, out, sizeof(out));
    OK(n > 0 && eq_hex(out, n, EXP_AAD_CONF), "phantom AAD byte identical to the reference");

    // Empty option
    n = sec_build_e_aad(osc, &req, opt, 0, osc->sender_context->sender_cred, out, sizeof(out));
    OK(!eq_hex(out, n, EXP_AAD_CONF), "empty-option AAD fails to match");

    // INIT_NOTIF
    opt_len = unhex("290152", opt, sizeof(opt));
    n = sec_build_e_aad(osc, &req, opt, opt_len, osc->sender_context->sender_cred, out, sizeof(out));
    OK(n > 0 && eq_hex(out, n, EXP_AAD_NOTIF("4100", "43290152")), "INIT_NOTIF AAD matches the reference");

    // wire notification
    opt_len = unhex("290252", opt, sizeof(opt));
    n = sec_build_e_aad(osc, &req, opt, opt_len, osc->sender_context->sender_cred, out, sizeof(out));
    OK(n > 0 && eq_hex(out, n, EXP_AAD_NOTIF("4100", "43290252")), "wire notification AAD matches");

    // changed credential
    n = sec_build_e_aad(osc, &req, opt, opt_len, osc->recipient_chain->rem_cred, out, sizeof(out));
    OK(!eq_hex(out, n, EXP_AAD_NOTIF("4100", "43290252")), "changed credential fails to match");

    coap_free_context(ctx);
    coap_cleanup();
    DONE();
}
