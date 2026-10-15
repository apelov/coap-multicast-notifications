#include "sec_state.h"
#include "sec_group.h"
#include <string.h>

void sec_srv_gobs_start(sec_srv_gobs_t *g, sec_grp_t *grp, const char *uri_path, const uint8_t *T, size_t tkl) {
    if (!g) return;
    memset(g, 0, sizeof(*g));
    if (!T || !tkl || tkl > sizeof(g->token)) return;
    memcpy(g->token, T, tkl);
    g->token_len = tkl;
    g->ph_req_len = sizeof(g->ph_req);

    if (sec_phantom_protect(grp, uri_path, T, tkl, g->ph_req, &g->ph_req_len, &g->tuple)) {
        g->state = GOBS_ACTIVE;
    }
}

/* MO-15 §4.1 step 6 / §4.3: the stored latest multicast notification
 * becomes exactly the protected bytes that were sent.  The same call retires
 * INIT_NOTIF once the first wire notification goes out and restarts the
 * Max-Age clock, so a refresh is measured from the last transmission. */
int sec_srv_latest_replace(sec_srv_gobs_t *g, const uint8_t *ti, size_t ti_len,
                           uint64_t piv, unsigned max_age, coap_tick_t now) {
    if (!g || !ti || !ti_len || ti_len > sizeof(g->latest)) return -1;
    memcpy(g->latest, ti, ti_len);
    g->latest_len = ti_len;
    g->latest_piv = piv;
    g->latest_is_init = 0;
    g->latest_created = now;
    /* No Inner Max-Age option is carried, so §4.3's "60 seconds otherwise"
     * applies; the server's -M overrides it for shorter test runs. */
    g->latest_max_age = max_age ? max_age : SEC_NOTIF_DEFAULT_MAX_AGE;
    return 0;
}

int sec_srv_refresh_due(const sec_srv_gobs_t *g, coap_tick_t now) {
    if (!g || !g->latest_len || now < g->latest_created) return 0;
    unsigned max_age = g->latest_max_age ? g->latest_max_age : SEC_NOTIF_DEFAULT_MAX_AGE;
    /* §4.3 triggers on an age "greater than its indicated maximum age", so an
     * age of exactly max_age seconds is still fresh. */
    return (now - g->latest_created) / COAP_TICKS_PER_SECOND > max_age;
}

void sec_cli_gobs_clear(sec_cli_gobs_t *g) {
    if (g) memset(g, 0, sizeof(*g));
}

int sec_cli_gobs_bind(sec_cli_gobs_t *g, const sec_tuple_t *tuple,
                      const uint8_t *token, size_t token_len,
                      const char *srv_host, uint16_t srv_port,
                      const char *grp_host, uint16_t grp_port) {
    if (!g || !tuple || !token || !token_len || token_len > sizeof(g->token) ||
        !srv_host || !grp_host || !*srv_host || !*grp_host || !srv_port || !grp_port ||
        strlen(srv_host) >= sizeof(g->srv_addr) ||
        strlen(grp_host) >= sizeof(g->grp_addr)) return 0;
    sec_cli_gobs_clear(g);
    g->tuple = *tuple;
    g->tuple_valid = 1;
    memcpy(g->token, token, token_len);
    g->token_len = token_len;
    memcpy(g->srv_addr, srv_host, strlen(srv_host) + 1);
    g->srv_port = srv_port;
    memcpy(g->grp_addr, grp_host, strlen(grp_host) + 1);
    g->grp_port = grp_port;
    return 1;
}

int sec_cli_accept(sec_cli_gobs_t *g, uint64_t piv) {
    if (!g) return 0;
    if (g->rn_valid && piv <= g->rn) {
        g->rejected++;
        return 0;
    }
    g->rn_valid = 1;
    g->rn = piv;
    g->delivered++;
    return 1;
}
