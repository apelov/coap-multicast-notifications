#include "tap.h"
#include "../../src/sec/sec_group.h"
#include "../../src/sec/sec_ti.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap_internal.h>
#include <stdlib.h>
#include <string.h>

/* All key material comes from the published MO-15 section 10 fixtures. */
static coap_context_t *group_context(const char *path) {
    sec_config_t cfg;
    char text[2048];
    if (sec_config_load(path, &cfg) < 0 ||
        sec_conf_group_text(&cfg, text, sizeof(text)) < 0) return NULL;
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) return NULL;
    coap_str_const_t config = { strlen(text), (const uint8_t *)text };
    coap_oscore_conf_t *oc = coap_new_oscore_conf(config, NULL, NULL, cfg.group_start_sn);
    if (!oc || !coap_context_oscore_server(ctx, oc) || !ctx->p_osc_ctx) {
        coap_free_context(ctx);
        return NULL;
    }
    return ctx;
}

/* GO-28 section 3.4: use the exact same key, nonce and ciphertext while
 * varying only the OSCORE_option field of external_aad. */
static int aad_opens(coap_context_t *ctx, const uint8_t *option, size_t opt_len,
                     size_t aad_option_len, const uint8_t *ciphertext, size_t ct_len) {
    cose_encrypt0_t cose[1];
    uint8_t ext[600], aad[700], nonce_buf[13], plain[256];
    coap_bin_const_t nonce = { sizeof(nonce_buf), nonce_buf };
    coap_bin_const_t aad_bin;
    oscore_ctx_t *osc = ctx->p_osc_ctx;
    cose_encrypt0_init(cose);
    if (!oscore_decode_option_value(option, opt_len, cose)) return 0;
    cose_encrypt0_set_alg(cose, osc->alg_group_enc);
    oscore_generate_nonce(cose, osc, nonce_buf, sizeof(nonce_buf));
    cose_encrypt0_set_nonce(cose, &nonce);
    cose_encrypt0_set_key(cose, osc->sender_context->sender_key);
    cose_encrypt0_set_ciphertext(cose, (uint8_t *)ciphertext, ct_len);
    size_t ext_len = oscore_prepare_e_aad(osc, cose, option, aad_option_len,
                                           osc->sender_context->sender_cred,
                                           OSCORE_MODE_GROUP, ext, sizeof(ext));
    aad_bin.s = aad;
    aad_bin.length = oscore_prepare_aad(ext, ext_len, aad, sizeof(aad));
    cose_encrypt0_set_aad(cose, &aad_bin);
    return cose_encrypt0_decrypt(cose, plain, sizeof(plain)) > 0;
}

int main(void) {
    coap_startup();
    coap_context_t *server = group_context("docs/secure/examples/section10/server.conf");
    coap_context_t *client = group_context("docs/secure/examples/section10/client1.conf");
    OK(server && client, "published section10 group contexts load");
    if (!server || !client) DONE();

    coap_set_log_level(COAP_LOG_ERR);

    sec_grp_t grp = { server };
    sec_srv_gobs_t gobs;
    const uint8_t token[] = { 0x7b };
    sec_srv_gobs_start(&gobs, &grp, "r", token, sizeof(token));
    OK(gobs.state == GOBS_ACTIVE && gobs.ph_req_len > 0,
       "phantom protected on first registration");
    if (gobs.state != GOBS_ACTIVE) DONE();
    OK(server->p_osc_ctx->sender_context->group_mode &&
       server->p_osc_ctx->sender_context->seq == 502,
       "group Sender Context consumed SN 501 once (MO-15 section 9.2.1)");
    OK(gobs.tuple.kid_len == 1 && gobs.tuple.kid[0] == 0x05 &&
       gobs.tuple.piv_len == 2 && gobs.tuple.piv[0] == 0x01 && gobs.tuple.piv[1] == 0xf5 &&
       gobs.tuple.kid_ctx_len == 3 &&
       memcmp(gobs.tuple.kid_ctx, "\x57\xab\x2e", 3) == 0,
       "option tuple is kid 05, PIV 01f5, Gid 57ab2e");

    /* MO-15 section 4.2.2: synthesize only a local UDP envelope for parsing. */
    uint8_t udp[4 + sizeof(token) + sizeof(gobs.ph_req)];
    udp[0] = 0x51; /* version 1, NON, TKL 1 */
    udp[1] = gobs.ph_req[0];
    udp[2] = udp[3] = 0;
    udp[4] = token[0];
    memcpy(udp + 5, gobs.ph_req + 1, gobs.ph_req_len - 1);
    coap_pdu_t *outer = coap_pdu_init(0, 0, 0, sizeof(udp));
    OK(gobs.ph_req[0] == COAP_REQUEST_CODE_FETCH &&
       coap_pdu_parse(COAP_PROTO_UDP, udp, 4 + sizeof(token) + gobs.ph_req_len - 1, outer),
       "ph_req begins with 0x05 FETCH and omits UDP header, MID and Token");
    coap_opt_iterator_t oi;
    coap_opt_t *opt, *oscore_opt = NULL;
    unsigned options = 0;
    int outer_only = 1;
    coap_option_iterator_init(outer, &oi, COAP_OPT_ALL);
    while ((opt = coap_option_next(&oi))) {
        options++;
        if (oi.number == COAP_OPTION_OSCORE) oscore_opt = opt;
        else if (oi.number != COAP_OPTION_OBSERVE) outer_only = 0;
    }
    OK(options == 2 && outer_only && oscore_opt &&
       coap_check_option(outer, COAP_OPTION_OBSERVE, &oi),
       "outer options are Observe and OSCORE only (MO-15 section 9.2.2)");
    size_t payload_len = 0;
    const uint8_t *payload = NULL;
    OK(coap_get_data(outer, &payload_len, &payload) && payload_len > 64 + 8,
       "payload marker carries ciphertext plus 64-byte encrypted signature");
    const uint8_t *option = coap_opt_value(oscore_opt);
    size_t opt_len = coap_opt_length(oscore_opt);
    sec_tuple_t parsed;
    OK((option[0] & 0x20) && sec_tuple_from_option(option, opt_len, &parsed) &&
       memcmp(&parsed, &gobs.tuple, sizeof(parsed)) == 0,
       "group flag and stored tuple come from finalized OSCORE option");
    OK(aad_opens(server, option, opt_len, opt_len, payload, payload_len - 64),
       "AEAD verifies with actual OSCORE option in external_aad");
    OK(!aad_opens(server, option, opt_len, 0, payload, payload_len - 64),
       "empty-option external_aad does not verify");

    /* GO-28 section 7.2: an independent Recipient Context checks the
     * countersignature and decrypts the intended inner request. */
    coap_session_t *session = calloc(1, sizeof(*session));
    session->context = client;
    session->proto = COAP_PROTO_UDP;
    session->type = COAP_SESSION_TYPE_SERVER;
    session->recipient_ctx = client->p_osc_ctx->recipient_chain;
    coap_pdu_t *inner = NULL;
    coap_lock_lock(goto after_decrypt);
    inner = coap_oscore_decrypt_pdu(session, outer);
    coap_lock_unlock();
after_decrypt:
    opt = inner ? coap_check_option(inner, COAP_OPTION_URI_PATH, &oi) : NULL;
    OK(inner && coap_pdu_get_code(inner) == COAP_REQUEST_CODE_GET && opt &&
       coap_opt_length(opt) == 1 && coap_opt_value(opt)[0] == 'r' &&
       coap_check_option(inner, COAP_OPTION_OBSERVE, &oi),
       "independent recipient verifies signature and decrypts GET/Observe 0/Uri-Path");
    coap_delete_pdu(inner);
    coap_delete_pdu(outer);
    coap_lock_lock(goto after_cleanup);
    oscore_delete_server_associations(session);
    coap_lock_unlock();
after_cleanup:
    free(session);
    coap_free_context(client);
    coap_free_context(server);
    coap_cleanup();
    DONE();
}
