#include "tap.h"
#include "../../src/sec/sec_group.h"
#include "../../src/sec/sec_ti.h"
#include "../../src/sec/sec_state.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap_internal.h>
#include <stdlib.h>
#include <string.h>

/* Published fixture: a ph_req captured from the Java peer (UDP wrapper, empty OSCORE option in the AAD).
 * It uses only the public java-demo credentials. */
static const char java_phreq_hex[] =
    "580524a82b778c3607245231603739000344616c52ff"
    "aaec919bd0e7ab1eb53a96aa6584687cbacc5d934cf1bc98c996f76c0b0ee91a1a0e00ca118e8748f3b4be85d9db6700ea2e9cf198e505d91bc0a3e8521146a05293c79bc67de78fd6ba89959d018f5ce7778da7773b";

static size_t decode_hex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (strlen(hex) != 2 * n || n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

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

int main(void) {
    coap_startup();
    coap_context_t *server = group_context("docs/secure/examples/section10/server.conf");
    coap_context_t *client = group_context("docs/secure/examples/section10/client1.conf");
    OK(server && client, "contexts load");
    if (!server || !client) DONE();

    coap_set_log_level(COAP_LOG_ERR);

    sec_grp_t sgrp = { server };
    sec_srv_gobs_t gobs;
    const uint8_t token[] = { 0x7b };
    sec_srv_gobs_start(&gobs, &sgrp, "r", token, sizeof(token));

    sec_grp_t cgrp = { client };
    sec_tuple_t parsed;

    // server Recipient Context memcmp-identical before/after a valid AND an invalid ph_req
    oscore_recipient_ctx_t *rc = client->p_osc_ctx->recipient_chain;
    /* GO-28 §2.6.1 requires a valid group replay window. The fork defaults
     * to the RFC 8613 Echo bootstrap state, which does not replay-check. */
    rc->initial_state = 0;
    rc->last_seq = 0;
    rc->sliding_window = 0;
    oscore_recipient_ctx_t before;
    memcpy(&before, rc, sizeof(before));

    int ok = sec_phantom_verify(&cgrp, gobs.ph_req, gobs.ph_req_len, token, sizeof(token), "r", 0, &parsed);
    OK(ok, "ph_req verifies (valid)");

    OK(memcmp(&before, rc, sizeof(before)) == 0, "Recipient Context unchanged after valid verify");
    OK(parsed.kid_len == gobs.tuple.kid_len && memcmp(parsed.kid, gobs.tuple.kid, parsed.kid_len) == 0 &&
       parsed.piv_len == gobs.tuple.piv_len && memcmp(parsed.piv, gobs.tuple.piv, parsed.piv_len) == 0 &&
       parsed.kid_ctx_len == gobs.tuple.kid_ctx_len && memcmp(parsed.kid_ctx, gobs.tuple.kid_ctx, parsed.kid_ctx_len) == 0,
       "stored Tuple equals the server's");

    sec_cli_gobs_t association = {0};
    OK(association.token_len == 0 && association.tuple_valid == 0,
       "verification alone does not bind T");
    OK(sec_cli_gobs_bind(&association, &parsed, token, sizeof(token),
                         "127.0.0.1", 5683, "224.0.1.187", 61616) &&
       association.tuple_valid && association.token_len == sizeof(token) &&
       memcmp(association.token, token, sizeof(token)) == 0 &&
       memcmp(&association.tuple, &gobs.tuple, sizeof(parsed)) == 0 &&
       strcmp(association.srv_addr, "127.0.0.1") == 0 && association.srv_port == 5683 &&
       strcmp(association.grp_addr, "224.0.1.187") == 0 && association.grp_port == 61616,
       "verified Tuple and T bind to server and group endpoints");

    int ok2 = sec_phantom_verify(&cgrp, gobs.ph_req, gobs.ph_req_len, token, sizeof(token), "r", 0, &parsed);
    OK(ok2, "the same ph_req verifies twice (no replay check)");
    OK(client->sendqueue == NULL && client->endpoint == NULL &&
       client->sessions == NULL && client->resources == NULL,
       "phantom verification queues no datagram, registers no token or callback");

    uint8_t bad_req[256];
    memcpy(bad_req, gobs.ph_req, gobs.ph_req_len);
    bad_req[gobs.ph_req_len - 1] ^= 0x01; // one-byte tamper
    int ok_bad = sec_phantom_verify(&cgrp, bad_req, gobs.ph_req_len, token, sizeof(token), "r", 0, &parsed);
    OK(!ok_bad, "one-byte tamper rejected");

    sec_cli_gobs_clear(&association);
    OK(!association.tuple_valid && !association.token_len && !association.grp_port &&
       !association.srv_port && !association.tuple.kid_len,
       "verification failure clears the association");

    OK(memcmp(&before, rc, sizeof(before)) == 0, "Recipient Context unchanged after invalid verify");

    // 1. Mismatching authenticated request (Observe=1)
    uint8_t bad_ph[256];
    size_t bad_len = sizeof(bad_ph);

    // We can simulate an invalid phantom directly by constructing one.
    coap_pdu_t *plain = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET, 0, 256);
    coap_add_token(plain, sizeof(token), token);
    coap_add_option(plain, COAP_OPTION_OBSERVE, 1, (const uint8_t *)"\x01");
    coap_add_option(plain, COAP_OPTION_URI_PATH, 1, (const uint8_t *)"r");

    coap_session_t *sess = calloc(1, sizeof(coap_session_t));
    sess->context = server;
    sess->proto = COAP_PROTO_UDP;
    sess->type = COAP_SESSION_TYPE_CLIENT;
    sess->recipient_ctx = server->p_osc_ctx->recipient_chain;

    coap_pdu_t *osc = coap_oscore_new_pdu_encrypted(sess, plain, NULL, OSCORE_SEND_PARTIAL_IV);
    coap_delete_pdu(plain);
    bad_len = sec_ti_export(osc, bad_ph, bad_len);
    coap_delete_pdu(osc);
    oscore_delete_server_associations(sess);
    free(sess);

    int ok_obs1 = sec_phantom_verify(&cgrp, bad_ph, bad_len, token, sizeof(token), "r", 0, &parsed);
    OK(!ok_obs1, "mismatching authenticated request (Observe=1) rejected");

    // 2. Normal verification followed by replay rejection
    coap_pdu_t *norm_pdu = NULL;
    sec_ti_import(gobs.ph_req, gobs.ph_req_len, token, sizeof(token), 1, 0, &norm_pdu);

    coap_session_t *sess2 = calloc(1, sizeof(coap_session_t));
    sess2->context = client;
    sess2->proto = COAP_PROTO_UDP;
    sess2->type = COAP_SESSION_TYPE_SERVER;
    sess2->recipient_ctx = client->p_osc_ctx->recipient_chain;

    coap_pdu_t *dec1 = NULL;
    coap_lock_lock(goto normal_cleanup);
    dec1 = coap_oscore_decrypt_pdu_ext(sess2, norm_pdu, 0);
    coap_lock_unlock();
    OK(dec1 != NULL, "normal replay protection: first verify succeeds");
    if (dec1) coap_delete_pdu(dec1);

    OK(memcmp(&before, rc, sizeof(before)) != 0, "normal replay protection: window updated");

    coap_pdu_t *norm_pdu2 = NULL;
    sec_ti_import(gobs.ph_req, gobs.ph_req_len, token, sizeof(token), 1, 0, &norm_pdu2);
    coap_pdu_t *dec2 = NULL;
    coap_lock_lock(goto normal_cleanup);
    dec2 = coap_oscore_decrypt_pdu_ext(sess2, norm_pdu2, 0);
    coap_lock_unlock();
    OK(dec2 == NULL, "normal replay protection: replayed request rejected");
    if (dec2) coap_delete_pdu(dec2);
normal_cleanup:
    oscore_delete_server_associations(sess2);
    free(sess2);

    // 3. Negative test for Java wrapper
    uint8_t malf_wrap[256];
    malf_wrap[0] = 0x41; // TKL=1
    malf_wrap[1] = COAP_REQUEST_CODE_GET;
    malf_wrap[2] = 0; malf_wrap[3] = 0;
    malf_wrap[4] = 0xaa; // wrong token
    memcpy(malf_wrap + 5, gobs.ph_req, gobs.ph_req_len);

    int ok_java_bad = sec_phantom_verify(&cgrp, malf_wrap, gobs.ph_req_len + 5, token, sizeof(token), "r", 1, &parsed);
    OK(!ok_java_bad, "malformed Java UDP wrapper rejected");
    malf_wrap[0] = 0x42; /* header says TKL 2 but T is one byte */
    OK(!sec_phantom_verify(&cgrp, malf_wrap, gobs.ph_req_len + 5,
                           token, sizeof(token), "r", 1, &parsed),
       "Java wrapper with mismatching TKL rejected");

    uint8_t java_phreq[256];
    size_t java_len = decode_hex(java_phreq_hex, java_phreq, sizeof(java_phreq));
    const uint8_t java_token[] = {0x2b,0x77,0x8c,0x36,0x07,0x24,0x52,0x31};
    coap_context_t *java_client = group_context("docs/secure/examples/java-demo/client1.conf");
    sec_grp_t jgrp = { java_client };
    OK(java_client != NULL, "Java demo context loads");
    OK(java_len == 108, "published Java ph_req fixture decoded");
    OK(!sec_phantom_verify(&jgrp, java_phreq, java_len, java_token,
                           sizeof(java_token), "OSCORE-mult", 0, &parsed),
       "Java wrapper rejected by default");
    OK(!sec_phantom_verify(&jgrp, java_phreq, java_len, java_token,
                           sizeof(java_token), "OSCORE-mult", 1, &parsed),
       "Java empty AAD rejected without the compat switch");
    OK(sec_phantom_verify(&jgrp, java_phreq, java_len, java_token,
                          sizeof(java_token), "OSCORE-mult", 3, &parsed),
       "Java fixture verifies with both explicit compatibility switches");

    coap_free_context(java_client);
    coap_free_context(client);

    coap_free_context(server);
    coap_cleanup();
    DONE();
}
