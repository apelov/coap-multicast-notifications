/* MO-15 §4.1 step 6 and §4.3: the stored latest multicast notification
 * is replaced by exactly the protected bytes that were sent, and a refresh is
 * due once that stored notification has reached an age greater than its
 * maximum age (60 s when it carries no Inner Max-Age option). */

#include "tap.h"
#include "../../src/sec/sec_group.h"
#include "../../src/sec/sec_ti.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap_internal.h>
#include <stdlib.h>
#include <string.h>

#define T0 1000   /* an arbitrary fixed tick for the stored notification */

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

static int stored_is(const sec_srv_gobs_t *g, const uint8_t *ti, size_t ti_len) {
    return g->latest_len == ti_len && memcmp(g->latest, ti, ti_len) == 0;
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
    sec_tuple_t ver;
    sec_phantom_verify(&cgrp, sgobs.ph_req, sgobs.ph_req_len, token, sizeof(token), "r", 0, &ver);

    uint8_t udp[1024], ti_init[1024], ti_wire[1024];
    size_t udp_len, ti_init_len, ti_wire_len;
    uint64_t init_piv = 0, wire_piv = 0;

    int pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 1,
                               (const uint8_t *)"init", 4, 0, 0,
                               udp, &udp_len, ti_init, &ti_init_len, &init_piv);
    OK(pr && init_piv == 502, "INIT_NOTIF protects (PIV 502)");
    OK(ti_init_len <= sizeof(sgobs.latest), "latest[] holds the protected notification");

    // Nothing stored yet: no refresh is due and a replacement needs bytes.
    OK(!sec_srv_refresh_due(&sgobs, T0 + 3600 * COAP_TICKS_PER_SECOND), "no stored notification -> no refresh");
    OK(sec_srv_latest_replace(&sgobs, NULL, 0, init_piv, 0, T0) < 0, "empty replacement refused");

    // Store INIT_NOTIF exactly as the server does at group-observation start.
    OK(sec_srv_latest_replace(&sgobs, ti_init, ti_init_len, init_piv, 0, T0) == 0, "INIT_NOTIF stored");
    OK(stored_is(&sgobs, ti_init, ti_init_len), "stored bytes are the protected INIT_NOTIF verbatim");
    OK(sgobs.latest_piv == init_piv && sgobs.latest_created == T0, "PIV and creation tick stored");
    OK(sgobs.latest_max_age == SEC_NOTIF_DEFAULT_MAX_AGE, "no Max-Age option -> 60 s default");
    sgobs.latest_is_init = 1;

    // §4.3: due once the stored notification is *older* than its maximum age.
    OK(!sec_srv_refresh_due(&sgobs, T0 + 60 * COAP_TICKS_PER_SECOND), "age == max age is not yet expired");
    OK(!sec_srv_refresh_due(&sgobs, T0 + 61 * COAP_TICKS_PER_SECOND - 1), "one tick before expiry is not due");
    OK(sec_srv_refresh_due(&sgobs, T0 + 61 * COAP_TICKS_PER_SECOND), "refresh due one second after max age");

    // An explicit -M is honoured.
    OK(sec_srv_latest_replace(&sgobs, ti_init, ti_init_len, init_piv, 5, T0) == 0, "re-stored with -M 5");
    OK(sgobs.latest_max_age == 5, "-M 5 stored as max age");
    OK(!sec_srv_refresh_due(&sgobs, T0 + 5 * COAP_TICKS_PER_SECOND), "-M 5: fresh at age 5");
    OK(sec_srv_refresh_due(&sgobs, T0 + 6 * COAP_TICKS_PER_SECOND), "-M 5: due at age 6");

    // The first wire notification replaces INIT_NOTIF byte for byte.
    pr = sec_notif_protect(&sgrp, &sgobs.tuple, token, sizeof(token), 2,
                           (const uint8_t *)"wire", 4, 0, 0,
                           udp, &udp_len, ti_wire, &ti_wire_len, &wire_piv);
    OK(pr && wire_piv == 503, "wire notification protects (PIV 503)");
    OK(sec_srv_latest_replace(&sgobs, ti_wire, ti_wire_len, wire_piv, 0, T0 + 7000) == 0,
       "wire notification replaces the stored one");
    OK(stored_is(&sgobs, ti_wire, ti_wire_len), "stored bytes are the sent notification, not INIT_NOTIF");
    OK(!sgobs.latest_is_init, "INIT_NOTIF replaced by the first wire notification");
    OK(sgobs.latest_piv == wire_piv && sgobs.latest_created == T0 + 7000, "PIV and tick follow the replacement");
    OK(sgobs.latest_max_age == SEC_NOTIF_DEFAULT_MAX_AGE, "replacement restores the 60 s default");
    OK(!sec_srv_refresh_due(&sgobs, T0 + 7000 + 60 * COAP_TICKS_PER_SECOND), "replacement restarts the age");

    // A client joining late receives those exact bytes and verifies them.
    coap_pdu_t *pdu = NULL;
    sec_ti_import(sgobs.latest, sgobs.latest_len, token, sizeof(token), 0, 0, &pdu);
    OK(pdu != NULL, "stored latest notification parses as a response");
    uint64_t rpiv = 0;
    uint8_t pt[256];
    size_t pt_len = 0;
    OK(sec_notif_verify(&cgrp, &ver, pdu, 0, &rpiv, pt, &pt_len) && rpiv == wire_piv,
       "late client verifies the stored latest notification");
    /* 2.05 | inner Observe (empty) | Content-Format text/plain | payload marker | payload */
    OK(pt_len == 8 && pt[0] == 0x45 && pt[1] == 0x60 && pt[2] == 0x60 && pt[3] == 0xFF &&
       memcmp(pt + 4, "wire", 4) == 0, "stored notification carries the sent payload");
    coap_delete_pdu(pdu);

    // An oversized replacement is refused and leaves the stored bytes alone.
    uint8_t big[sizeof(sgobs.latest) + 1];
    memset(big, 0xa5, sizeof(big));
    OK(sec_srv_latest_replace(&sgobs, big, sizeof(big), 1, 0, T0) < 0, "oversized replacement refused");
    OK(stored_is(&sgobs, ti_wire, ti_wire_len), "refused replacement left the stored bytes untouched");
    OK(sgobs.latest_piv == wire_piv, "refused replacement left the stored PIV untouched");

    coap_free_context(client);
    coap_free_context(server);
    coap_cleanup();
    DONE();
}
