#include "tap.h"
#include "../../src/sec/sec_group.h"
#include "../../src/sec/sec_ti.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap_internal.h>
#include <stdlib.h>
#include <string.h>

static coap_context_t *group_context(const char *path) {
    sec_config_t cfg;
    char text[2048];
    if (sec_config_load(path, &cfg) < 0 || sec_conf_group_text(&cfg, text, sizeof(text)) < 0) return NULL;
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

    sec_grp_t sgrp = { server };
    sec_srv_gobs_t sgobs;
    const uint8_t token[] = { 0x7b };
    sec_srv_gobs_start(&sgobs, &sgrp, "r", token, sizeof(token));

    sec_grp_t cgrp = { client };
    sec_cli_gobs_t cgobs;
    sec_cli_gobs_clear(&cgobs);

    sec_tuple_t ver;
    sec_phantom_verify(&cgrp, sgobs.ph_req, sgobs.ph_req_len, token, sizeof(token), "r", 0, &ver);
    sec_cli_gobs_bind(&cgobs, &ver, token, sizeof(token), "127", 5683, "224", 5683);

    uint8_t udp1[1024], ti1[1024]; size_t udp_len1, ti_len1; uint64_t piv1 = 0;
    uint8_t udp2[1024], ti2[1024]; size_t udp_len2, ti_len2; uint64_t piv2 = 0;
    uint8_t udp3[1024], ti3[1024]; size_t udp_len3, ti_len3; uint64_t piv3 = 0;

    int pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 1, (const uint8_t *)"1234", 4, 0, 0, udp1, &udp_len1, ti1, &ti_len1, &piv1);
    OK(pr && piv1 == 502, "INIT_NOTIF consumes SN 502");

    pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 2, (const uint8_t *)"5678", 4, 0, 0, udp2, &udp_len2, ti2, &ti_len2, &piv2);
    OK(pr && piv2 == 503, "first wire notification consumes SN 503");

    pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 3, (const uint8_t *)"9012", 4, 0, 0, udp3, &udp_len3, ti3, &ti_len3, &piv3);
    OK(pr && piv3 == 504, "second wire notification consumes SN 504");

    coap_pdu_t *pdu = NULL;
    sec_ti_import(ti2, ti_len2, token, sizeof(token), 0, 0, &pdu);

    uint64_t rpiv = 0;
    uint8_t pt[256];
    size_t pt_len = 0;
    int verif = sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len);
    OK(verif && rpiv == 503, "first wire notification verifies");

    int acc = sec_cli_accept(&cgobs, rpiv);
    OK(acc && cgobs.rn == 503, "first wire notification accepted");

    // Replay
    acc = sec_cli_accept(&cgobs, rpiv);
    OK(!acc && cgobs.rn == 503, "replay rejected");

    // Next notification
    coap_delete_pdu(pdu);
    pdu = NULL;
    sec_ti_import(ti3, ti_len3, token, sizeof(token), 0, 0, &pdu);
    verif = sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len);
    acc = sec_cli_accept(&cgobs, rpiv);
    OK(verif && acc && cgobs.rn == 504, "second wire notification accepted");

    // Tamper payload — GO-28 §7.4: RN and delivered MUST NOT change
    uint64_t pre_rn = cgobs.rn;
    unsigned pre_delivered = cgobs.delivered;
    coap_delete_pdu(pdu);
    ti1[ti_len1 - 1] ^= 1;
    pdu = NULL;
    sec_ti_import(ti1, ti_len1, token, sizeof(token), 0, 0, &pdu);
    verif = sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len);
    OK(!verif, "tamper -> verification fails");
    OK(cgobs.rn == pre_rn, "tamper -> RN unchanged");
    OK(cgobs.delivered == pre_delivered, "tamper -> delivered unchanged");
    coap_delete_pdu(pdu);

    // Alter AAD in ver (client side)
    pdu = NULL;
    sec_ti_import(ti2, ti_len2, token, sizeof(token), 0, 0, &pdu);

    sec_tuple_t bad_ver = ver;
    bad_ver.kid[0] ^= 1;
    OK(!sec_notif_verify(&cgrp, &bad_ver, pdu, 0, &rpiv, pt, &pt_len), "altered kid fails");

    bad_ver = ver;
    bad_ver.piv[0] ^= 1;
    OK(!sec_notif_verify(&cgrp, &bad_ver, pdu, 0, &rpiv, pt, &pt_len), "altered piv fails");

    bad_ver = ver;
    bad_ver.kid_ctx[0] ^= 1;
    OK(!sec_notif_verify(&cgrp, &bad_ver, pdu, 0, &rpiv, pt, &pt_len), "altered kid_ctx/Gid fails");

    coap_delete_pdu(pdu);

    /* GO-28 §7.4 sender binding: a cryptographically valid notification
     * from a *different* group member (client1, kid=25) must be rejected
     * because the Tuple's kid is 05.  The server context has a Recipient
     * for kid=25 so oscore_find_context would succeed without the gate. */
    coap_context_t *client1_sender = group_context("docs/secure/examples/section10/client1.conf");
    OK(client1_sender != NULL, "second sender context loads");
    if (client1_sender) {
        sec_grp_t c1grp = { client1_sender };
        sec_tuple_t c1tuple;
        uint8_t c1ph[256];
        size_t c1ph_len = sizeof(c1ph);
        /* Produce a phantom from client1 to get its Tuple (kid=25) */
        sec_phantom_protect(&c1grp, "r", token, sizeof(token), c1ph, &c1ph_len, &c1tuple);

        /* Protect a notification with client1's sender context */
        uint8_t c1udp[1024], c1ti[1024];
        size_t c1udp_len, c1ti_len;
        uint64_t c1piv = 0;
        int c1pr = sec_notif_protect(&c1grp, &c1tuple, token, sizeof(token), 1,
                                     (const uint8_t *)"abc", 3, 0, 0,
                                     c1udp, &c1udp_len, c1ti, &c1ti_len, &c1piv);
        OK(c1pr, "second sender notification protects");

        /* Try to verify on the server context (has Recipient for kid=25)
         * using the *server's* Tuple (kid=05).  The kid equality gate
         * must reject this before any crypto. */
        coap_pdu_t *c1pdu = NULL;
        sec_ti_import(c1ti, c1ti_len, token, sizeof(token), 0, 0, &c1pdu);
        sec_grp_t sverify = { server };
        OK(!sec_notif_verify(&sverify, &ver, c1pdu, 0, &rpiv, pt, &pt_len),
           "second sender kid!=Tuple kid -> rejected");
        coap_delete_pdu(c1pdu);
        coap_free_context(client1_sender);
    }

    coap_free_context(client);
    coap_free_context(server);
    coap_cleanup();
    DONE();
}
