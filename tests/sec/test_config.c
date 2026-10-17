#include "tap.h"
#include "../../src/sec/sec_config.h"
#include <coap3/coap.h>
#include <coap3/coap_internal.h>
#include <oscore/oscore_context.h>
#include <string.h>

/* Fork-only symbol distinguishes the patched archive from Homebrew's 4.3.5b. */
static coap_pdu_t *(*const fork_decrypt)(coap_session_t *, coap_pdu_t *, uint32_t) = coap_oscore_decrypt_pdu_ext;

static int same_bin(const coap_bin_const_t *a, const coap_bin_const_t *b) {
    return a && b && a->length == b->length && memcmp(a->s, b->s, a->length) == 0;
}

static oscore_ctx_t *derive(coap_context_t *coap, const sec_config_t *cfg, int pairwise, int slot) {
    char buf[4096];
    int rc = pairwise ? sec_conf_pairwise_text(cfg, slot, buf, sizeof(buf))
                      : sec_conf_group_text(cfg, buf, sizeof(buf));
    if (rc < 0) return NULL;
    coap_str_const_t text = {strlen(buf), (const uint8_t *)buf};
    uint64_t sn = pairwise ? (cfg->is_server ? cfg->pairwise_server[slot].start_sn
                                           : cfg->pairwise_client.start_sn)
                           : cfg->group_start_sn;
    coap_oscore_conf_t *parsed = coap_new_oscore_conf(text, NULL, NULL, sn);
    if (!parsed) return NULL;
    oscore_ctx_t *derived = oscore_derive_ctx(coap, parsed);
    coap_delete_oscore_conf(parsed);
    return derived;
}

int main(void) {
    OK(strcmp(LIBCOAP_PACKAGE_VERSION, "4.3.5") == 0 && fork_decrypt != NULL,
       "Patched fork version and scoped decrypt symbol available");
    coap_startup();
    coap_context_t *coap = coap_new_context(NULL);
    OK(coap != NULL, "Created derivation context");
    if (!coap) DONE();
    sec_config_t srv, cli;
    int rc;

    coap_set_log_level(COAP_LOG_ERR);

    rc = sec_config_load("docs/secure/examples/java-demo/server.conf", &srv);
    OK(rc == 0, "Loaded server.conf");
    OK(srv.is_server == 1, "Server role parsed");
    OK(strcmp(srv.group_gid, "44616c") == 0, "Server Gid correct");

    rc = sec_config_load("docs/secure/examples/java-demo/client1.conf", &cli);
    OK(rc == 0, "Loaded client1.conf");
    OK(cli.is_server == 0, "Client role parsed");
    OK(strcmp(cli.group_gid, "44616c") == 0, "Client Gid correct");

    OK(strcmp(srv.group_master_secret, cli.group_master_secret) == 0, "Group master secrets match");
    OK(strcmp(srv.pairwise_server[0].master_secret, cli.pairwise_client.master_secret) == 0, "Pairwise master secrets match");

    char buf[4096];
    rc = sec_conf_group_text(&srv, buf, sizeof(buf));
    OK(rc == 0, "Generated server group text");
    OK(strstr(buf, "44616c") != NULL, "Gid in group text");

    rc = sec_conf_pairwise_text(&cli, 0, buf, sizeof(buf));
    OK(rc == 0, "Generated client pairwise text");
    OK(strstr(buf, cli.pairwise_client.master_secret) != NULL, "Secret in pairwise text");

    const char *profiles[] = {"java-demo", "section10"};
    for (size_t profile = 0; profile < sizeof(profiles) / sizeof(profiles[0]); profile++) {
        char path[96];
        snprintf(path, sizeof(path), "docs/secure/examples/%s/server.conf", profiles[profile]);
        OK(sec_config_load(path, &srv) == 0, "Loaded %s server fixture", profiles[profile]);
        for (int slot = 0; slot < 2; slot++) {
            snprintf(path, sizeof(path), "docs/secure/examples/%s/client%d.conf", profiles[profile], slot + 1);
            OK(sec_config_load(path, &cli) == 0, "Loaded %s client %d fixture", profiles[profile], slot + 1);
            oscore_ctx_t *sp = derive(coap, &srv, 1, slot);
            oscore_ctx_t *cp = derive(coap, &cli, 1, 0);
            OK(sp && cp, "Derived %s pairwise contexts for client %d", profiles[profile], slot + 1);
            if (sp && cp) {
                OK(same_bin(sp->common_iv, cp->common_iv), "Pairwise common IV matches %s client %d", profiles[profile], slot + 1);
                OK(same_bin(sp->sender_context->sender_key, cp->recipient_chain->recipient_key) &&
                   same_bin(sp->recipient_chain->recipient_key, cp->sender_context->sender_key),
                   "Pairwise sender/recipient keys cross-match %s client %d", profiles[profile], slot + 1);
            }
            oscore_ctx_t *sg = derive(coap, &srv, 0, 0);
            oscore_ctx_t *cg = derive(coap, &cli, 0, 0);
            OK(sg && cg, "Derived %s group contexts for client %d", profiles[profile], slot + 1);
            if (sg && cg) {
                OK(same_bin(sg->id_context, cg->id_context) && same_bin(sg->common_iv, cg->common_iv),
                   "Group Gid and common IV match %s client %d", profiles[profile], slot + 1);
                OK(same_bin(sg->sender_context->sender_key, cg->recipient_chain->recipient_key),
                   "Server group sender key matches %s client %d recipient key", profiles[profile], slot + 1);
            }
        }
    }

    coap_free_context(coap);
    coap_cleanup();
    DONE();
}
