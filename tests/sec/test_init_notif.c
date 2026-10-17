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
    sec_srv_gobs_t sgobs;
    const uint8_t token[] = { 0x7b };
    sec_srv_gobs_start(&sgobs, &sgrp, "r", token, sizeof(token));

    sec_grp_t cgrp = { client };
    sec_cli_gobs_t cgobs;
    sec_cli_gobs_clear(&cgobs);

    sec_tuple_t ver;
    sec_phantom_verify(&cgrp, sgobs.ph_req, sgobs.ph_req_len, token, sizeof(token), "r", 0, &ver);
    sec_cli_gobs_bind(&cgobs, &ver, token, sizeof(token), "127", 5683, "224", 5683);

    uint8_t udp[1024], ti[1024];
    size_t udp_len, ti_len;
    uint64_t piv = 0;

    // Protect INIT_NOTIF
    int pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 1, (const uint8_t *)"0", 1, 0, 0, udp, &udp_len, ti, &ti_len, &piv);
    OK(pr && piv == 502, "INIT_NOTIF PIV is 502");

    coap_pdu_t *pdu = NULL;
    int imp = sec_ti_import(ti, ti_len, token, sizeof(token), 0, 0, &pdu);
    OK(imp && pdu != NULL, "ti_import parses INIT_NOTIF as response");

    uint64_t rpiv = 0;
    uint8_t pt[256];
    size_t pt_len = 0;
    int verif = sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len);
    /* 2.05 | inner Observe (empty, RFC 8613 §4.1.3.5.2) | Content-Format text/plain (0-length)
     * | payload marker | payload */
    OK(verif && rpiv == 502 && pt_len == 5 &&
       pt[0] == 0x45 && pt[1] == 0x60 && pt[2] == 0x60 && pt[3] == 0xFF && pt[4] == '0',
       "INIT_NOTIF verifies correctly");

    int acc = sec_cli_accept(&cgobs, rpiv);
    OK(acc && cgobs.rn_valid && cgobs.rn == 502, "INIT_NOTIF accepted and RN initialized");

    coap_delete_pdu(pdu);

    // Tampered INIT_NOTIF
    ti[ti_len - 1] ^= 1; // alter countersignature
    pdu = NULL;
    sec_ti_import(ti, ti_len, token, sizeof(token), 0, 0, &pdu);
    verif = sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len);
    OK(!verif, "tampered INIT_NOTIF fails verification");

    sec_cli_gobs_t cgobs2;
    sec_cli_gobs_clear(&cgobs2);
    sec_cli_gobs_bind(&cgobs2, &ver, token, sizeof(token), "127", 5683, "224", 5683);
    acc = 0;
    if (verif) acc = sec_cli_accept(&cgobs2, rpiv);
    OK(!acc && !cgobs2.rn_valid, "tampered not delivered, RN unset, ph_req state kept");

    coap_delete_pdu(pdu);
    coap_free_context(client);
    coap_free_context(server);
    coap_cleanup();
    DONE();
}
