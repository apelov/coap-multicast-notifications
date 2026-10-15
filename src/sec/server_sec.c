#include <coap3/coap.h>
#include <coap3/coap_internal.h>
#include "sec_config.h"
#include "sec_debug.h"
#include "sec_ir.h"
#include "sec_state.h"
#include "sec_group.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

sec_config_t conf;
sec_srv_gobs_t gobs;
sec_grp_t grp_ctx;
const char *compat_list = "none";
char srv_bind_ip[64] = "127.0.0.1";
uint16_t srv_bind_port = 5683;
/* Max-Age of the stored latest notification, -M (MO-15 §4.3). */
unsigned srv_notif_max_age = SEC_NOTIF_DEFAULT_MAX_AGE;
static coap_context_t *uc_ctx;
static const char *next_val = "";

/* Message IDs for the multicast notification stream.
 *
 * RFC 7252 §4.4: "The same Message ID MUST NOT be reused (in communicating
 * with the same endpoint) within the EXCHANGE_LIFETIME" (247 s by default).
 * A constant MID would make a conformant receiver deduplicate all but the
 * first notification.
 *
 * Notifications are sent to GRP_ADDR:GRP_PORT by coap_mcast_send() with no
 * coap_session_t behind them, so coap_new_message_id() — which only
 * pre-increments session->tx_mid — has nothing to be called on.  Keep the
 * stream's own counter instead, seeded the way libcoap seeds every session
 * (coap_session.c draws tx_mid with coap_prng()): a random start means a
 * restarted server does not reissue an ID a client is still deduplicating,
 * and pre-incrementing means consecutive notifications never repeat.  At the
 * MO-15 §4.3 floor of one notification per three seconds the 16-bit space
 * turns over after more than two days, well past EXCHANGE_LIFETIME.
 *
 * MID 0 is legal — RFC 7252 §4.4 does not reserve it — but skipping it keeps
 * "did the wire stop saying MID=0?" an unambiguous signal in the interop
 * matrix decode dumps.
 */
static uint16_t notif_tx_mid;

static uint16_t notif_next_mid(void) {
    uint16_t mid = ++notif_tx_mid;
    return mid ? mid : ++notif_tx_mid;
}

/* The current representation: the next configured value, or the Observe
 * sequence number once the configured list is exhausted. */
static void next_value(char *buf, size_t len) {
    if (next_val && next_val[0]) {
        const char *comma = strchr(next_val, ',');
        if (comma) {
            snprintf(buf, len, "%.*s", (int)(comma - next_val), next_val);
            next_val = comma + 1;
        } else {
            snprintf(buf, len, "%s", next_val);
            next_val = "";
        }
    } else {
        snprintf(buf, len, "%d", gobs.observe + 1);
    }
}

/* Sending and replacement: protect the current representation, send
 * it as a multicast notification, and replace the stored latest notification
 * with exactly the bytes that were sent (MO-15 §4.1 step 6, §4.3).  The two
 * trailing zeros of sec_notif_protect() are `max_age` and `mid`; the Message
 * ID must come from notif_next_mid(), not from a literal 0, or every
 * notification repeats one ID within EXCHANGE_LIFETIME (RFC 7252 §4.4) and a
 * conformant receiver drops all but the first.  Returns 1
 * when a notification went out on the wire. */
static int notif_send_once(coap_tick_t now) {
    char state_str[64];
    next_value(state_str, sizeof(state_str));

    gobs.observe++;

    uint8_t udp_buf[1024];
    size_t udp_len;
    uint8_t ti_buf[1024];
    size_t ti_len;
    uint64_t piv = 0;

    if (!sec_notif_protect(&grp_ctx, &gobs.tuple, gobs.token, gobs.token_len, gobs.observe,
                           (const uint8_t *)state_str, strlen(state_str), 0, notif_next_mid(),
                           udp_buf, &udp_len, ti_buf, &ti_len, &piv)) return 0;
    if (!sec_mcast_send(uc_ctx, conf.group_addr, conf.group_port, udp_buf, udp_len)) return 0;

    printf("[MCAST-NOTIF] piv=%02llx observe=%u state=%s to %s:%u from %s:%u\n",
           (unsigned long long)piv, gobs.observe, state_str, conf.group_addr, conf.group_port,
           srv_bind_ip, srv_bind_port);
    gobs.notifs_sent++;
    if (sec_srv_latest_replace(&gobs, ti_buf, ti_len, piv, srv_notif_max_age, now) < 0)
        fprintf(stderr, "notif: latest notification of %zu bytes does not fit the stored buffer\n", ti_len);
    return 1;
}

static void hnd_observe(coap_resource_t *resource,
                        coap_session_t *session,
                        const coap_pdu_t *request,
                        const coap_string_t *query,
                        coap_pdu_t *response) {
    (void)resource; (void)query;

    /* libcoap hands the handler the decrypted inner request (MO-15 §10).
     * Registration is specifically GET, Observe=0, on this resource (§5.1). */
    coap_opt_iterator_t oi;
    coap_opt_t *observe = coap_check_option(request, COAP_OPTION_OBSERVE, &oi);
    coap_opt_t *path = coap_check_option(request, COAP_OPTION_URI_PATH, &oi);
    if (coap_pdu_get_code(request) != COAP_REQUEST_CODE_GET ||
        !observe || coap_decode_var_bytes(coap_opt_value(observe), coap_opt_length(observe)) != 0 ||
        !path || coap_opt_length(path) != strlen(conf.resource) ||
        memcmp(coap_opt_value(path), conf.resource, coap_opt_length(path)) != 0) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
        return;
    }

    coap_async_t *async = coap_find_async(session, coap_pdu_get_token(request));
    if (!async) {
        sec_dbg_pdu("RX PLAIN", "client", request);
        async = coap_register_async(session, request, 0);
        if (async) {
            coap_async_trigger(async);
        }
        return;
    }

    unsigned char ip_port[128];
    coap_print_addr(&session->addr_info.remote, ip_port, sizeof(ip_port));

    char kid_str[64] = "none";
    if (session->recipient_ctx && session->recipient_ctx->recipient_id) {
        coap_bin_const_t *kid = session->recipient_ctx->recipient_id;
        for (size_t i = 0; i < kid->length && i*2 < sizeof(kid_str)-1; i++) {
            sprintf(&kid_str[i*2], "%02x", kid->s[i]);
        }
    }

    coap_pdu_set_code(response, COAP_RESPONSE_CODE(503));
    coap_pdu_set_type(response, COAP_MESSAGE_CON);

    uint8_t cf_buf[2];
    coap_add_option(response, COAP_OPTION_CONTENT_FORMAT, coap_encode_var_safe(cf_buf, sizeof(cf_buf), 12), cf_buf);

    tp_info_t tp = {0};
    snprintf(tp.server_host, sizeof(tp.server_host), "%s", srv_bind_ip);
    tp.server_port = srv_bind_port;
    snprintf(tp.client_host, sizeof(tp.client_host), "%s", conf.group_addr);
    tp.client_port = conf.group_port;

    if (gobs.state == GOBS_NONE) {
        uint8_t p_tok[8];
        size_t p_tok_len = 0;
        if (strcmp(conf.phantom_token, "random") == 0) {
            if (coap_prng(p_tok, sizeof(p_tok))) p_tok_len = sizeof(p_tok);
        } else {
            size_t hex_len = strlen(conf.phantom_token);
            if (hex_len && hex_len % 2 == 0 && hex_len <= sizeof(p_tok) * 2) {
                p_tok_len = hex_len / 2;
                for (size_t i = 0; i < p_tok_len; i++) {
                    if (sscanf(&conf.phantom_token[i * 2], "%2hhx", &p_tok[i]) != 1) {
                        p_tok_len = 0;
                        break;
                    }
                }
            }
        }
        sec_srv_gobs_start(&gobs, &grp_ctx, conf.resource, p_tok, p_tok_len);
        if (gobs.state != GOBS_ACTIVE) {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
            return;
        }
        uint8_t udp_buf[1024];
        size_t udp_len;
        uint8_t ti_buf[1024];
        size_t ti_len;
        uint64_t piv = 0;
        coap_tick_t now;
        coap_ticks(&now);
        /* INIT_NOTIF is never transmitted (MO-15 §4.1 step 6), so it carries Observe 0
         * and the notifications actually sent on the wire start at Observe 1 and strictly
         * increase from there — the representation the Java server composes, and what a
         * client takes the starting point of its own Observe sequence from. */
        gobs.observe = 0;
        char initial_state[64] = "0";
        if (conf.values[0]) {
            const char *comma = strchr(conf.values, ',');
            if (comma) {
                snprintf(initial_state, sizeof(initial_state), "%.*s", (int)(comma - conf.values), conf.values);
            } else {
                snprintf(initial_state, sizeof(initial_state), "%s", conf.values);
            }
        }
        printf("[PHANTOM] token=");
        for (size_t i=0; i<gobs.token_len; i++) printf("%02x", gobs.token[i]);
        printf(" kid=");
        for (size_t i=0; i<gobs.tuple.kid_len; i++) printf("%02x", gobs.tuple.kid[i]);
        printf(" piv=");
        for (size_t i=0; i<gobs.tuple.piv_len; i++) printf("%02x", gobs.tuple.piv[i]);
        printf(" gid=");
        for (size_t i=0; i<gobs.tuple.kid_ctx_len; i++) printf("%02x", gobs.tuple.kid_ctx[i]);
        printf(" ph_req_len=%zu\n", gobs.ph_req_len);

        if (sec_notif_protect(&grp_ctx, &gobs.tuple, gobs.token, gobs.token_len, gobs.observe, (const uint8_t *)initial_state, strlen(initial_state), 0, 0, udp_buf, &udp_len, ti_buf, &ti_len, &piv) &&
            sec_srv_latest_replace(&gobs, ti_buf, ti_len, piv, srv_notif_max_age, now) == 0) {
            gobs.latest_is_init = 1;
            printf("[INIT_NOTIF] piv=%02x observe=%u state=%s\n", (unsigned)piv, gobs.observe, initial_state);
        } else {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
            return;
        }
    }

    /* MO-15 §4.1 step 4 and §9.2.2: every client receives the same T and
     * ph_req for this group observation, regardless of its unicast Token. */
    tp.token_len = gobs.token_len;
    memcpy(tp.token, gobs.token, tp.token_len);

    uint8_t *ir = NULL;
    size_t ir_len = 0;
    if (sec_ir_encode(&tp, gobs.ph_req, gobs.ph_req_len, gobs.latest, gobs.latest_len, &ir, &ir_len) < 0 ||
        !ir || !coap_add_data(response, ir_len, ir)) {
        free(ir);
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
        return;
    }
    gobs.observers++;
    printf("[REG] from %s kid=%s observers=%u\n", ip_port, kid_str, gobs.observers);
    sec_dbg_pdu("TX PLAIN", (const char *)ip_port, response);
    sec_dbg_bytes("TX PLAIN IR", ir, ir_len);
    free(ir);

    printf("[INFO-RESP] to %s type=CON separate=yes cbor_len=%zu\n", ip_port, ir_len);
}

int main(int argc, char **argv) {
    setlinebuf(stdout);
    int opt;
    char conf_path[256] = "";
    int interval_s = 10;
    uint64_t max_wire_notifs = 0;
    while ((opt = getopt(argc, argv, "c:A:p:i:n:M:d:C:")) != -1) {
        switch (opt) {
            case 'c': snprintf(conf_path, sizeof(conf_path), "%s", optarg); break;
            case 'A': snprintf(srv_bind_ip, sizeof(srv_bind_ip), "%s", optarg); break;
            case 'p': srv_bind_port = atoi(optarg); break;
            case 'i': interval_s = atoi(optarg); break;
            case 'n': max_wire_notifs = strtoull(optarg, NULL, 10); break;
            case 'M': srv_notif_max_age = atoi(optarg); break;
            case 'd': sec_debug_level = atoi(optarg); break;
            case 'C': compat_list = optarg; break;
            default: exit(1);
        }
    }

    if (!conf_path[0] || sec_config_load(conf_path, &conf) < 0) {
        fprintf(stderr, "Failed to load config\n");
        exit(1);
    }

    if (!conf.is_server) exit(1);

    printf("[SEC] coap_server_sec profile=%s config=%s bind=%s:%u compat=%s debug=%d\n",
           conf.profile_name, conf_path, srv_bind_ip, srv_bind_port, compat_list, sec_debug_level);

    coap_startup();
    sec_dbg_init(sec_debug_level);
    /* Same seeding libcoap gives every session's tx_mid (coap_session.c). */
    coap_prng((uint8_t *)&notif_tx_mid, sizeof(notif_tx_mid));
    uc_ctx = coap_new_context(NULL);
    if (!uc_ctx) exit(2);

    coap_address_t bind_addr;
    coap_address_init(&bind_addr);
    bind_addr.addr.sin.sin_family = AF_INET;
    bind_addr.addr.sin.sin_port = htons(srv_bind_port);
    if (inet_pton(AF_INET, srv_bind_ip, &bind_addr.addr.sin.sin_addr) != 1 ||
        bind_addr.addr.sin.sin_addr.s_addr == htonl(INADDR_ANY) ||
        IN_MULTICAST(ntohl(bind_addr.addr.sin.sin_addr.s_addr)) ||
        !srv_bind_port) {
        fprintf(stderr, "Server requires a concrete IPv4 bind address and nonzero port\n");
        exit(1);
    }
    bind_addr.size = sizeof(bind_addr.addr.sin);

    coap_endpoint_t *ep = coap_new_endpoint(uc_ctx, &bind_addr, COAP_PROTO_UDP);
    if (!ep) exit(2);

    for (int i = 0; i < conf.num_pairwise_clients; i++) {
        char buf[2048];
        if (sec_conf_pairwise_text(&conf, i, buf, sizeof(buf)) == 0) {
            coap_str_const_t osc_conf = { strlen(buf), (const uint8_t *)buf };
            coap_oscore_conf_t *oc = coap_new_oscore_conf(osc_conf, NULL, NULL, conf.pairwise_server[i].start_sn);
            if (oc) coap_context_oscore_server(uc_ctx, oc);
        }
    }

    grp_ctx.ctx = coap_new_context(NULL);
    if (!grp_ctx.ctx) exit(2);
    {
        char buf[2048];
        if (sec_conf_group_text(&conf, buf, sizeof(buf)) < 0) exit(2);
        coap_str_const_t osc_conf = { strlen(buf), (const uint8_t *)buf };
        coap_oscore_conf_t *oc = coap_new_oscore_conf(osc_conf, NULL, NULL, conf.group_start_sn);
        if (!oc || !coap_context_oscore_server(grp_ctx.ctx, oc) ||
            !grp_ctx.ctx->p_osc_ctx || !grp_ctx.ctx->p_osc_ctx->sender_context ||
            !grp_ctx.ctx->p_osc_ctx->sender_context->group_mode) exit(2);
    }

    coap_str_const_t *ruri = coap_make_str_const(conf.resource);
    /* MO-15 §9 requires the original registration to be protected too. */
    coap_resource_t *r = coap_resource_init(ruri, COAP_RESOURCE_FLAGS_OSCORE_ONLY);
    coap_register_request_handler(r, COAP_REQUEST_GET, hnd_observe);
    coap_register_request_handler(r, COAP_REQUEST_FETCH, hnd_observe);
    coap_add_resource(uc_ctx, r);

    coap_tick_t now, last_notif_time = 0;
    coap_ticks(&last_notif_time);
    if (srv_notif_max_age == 0) srv_notif_max_age = SEC_NOTIF_DEFAULT_MAX_AGE;
    next_val = conf.values;
    if (next_val && next_val[0]) {
        const char *comma = strchr(next_val, ',');
        if (comma) next_val = comma + 1;
        else next_val = "";
    }

    while (1) {
        coap_tick_t timeout = COAP_IO_WAIT;
        coap_ticks(&now);

        if (gobs.state == GOBS_ACTIVE) {
            if (max_wire_notifs > 0 && gobs.notifs_sent >= max_wire_notifs) {
                break;
            }

            /* MO-15 §4.3 a stored latest notification older than its
             * maximum age must be replaced by a new multicast notification
             * carrying the current representation. */
            if (sec_srv_refresh_due(&gobs, now)) {
                unsigned age_s = (unsigned)((now - gobs.latest_created) / COAP_TICKS_PER_SECOND);
                printf("[REFRESH] latest notification expired (age=%u max_age=%u)\n",
                       age_s, gobs.latest_max_age ? gobs.latest_max_age : SEC_NOTIF_DEFAULT_MAX_AGE);
                /* A refresh is a multicast notification like any other, so
                 * it must also push the periodic deadline out.  Leaving
                 * last_notif_time stale makes the very next iteration satisfy
                 * the periodic branch and emit a duplicate notification in
                 * the same tick (MO-15 section 4.4: at most one notification
                 * every 3 seconds). */
                if (notif_send_once(now)) { last_notif_time = now; continue; }
                timeout = COAP_TICKS_PER_SECOND;  /* retry the refresh in a second */
            }

            /* Wake up for the refresh deadline even when nothing else is due,
             * so -i 0 (no periodic changes) still refreshes on time. */
            if (gobs.latest_len) {
                unsigned max_age = gobs.latest_max_age ? gobs.latest_max_age : SEC_NOTIF_DEFAULT_MAX_AGE;
                coap_tick_t refresh_at = gobs.latest_created + (max_age + 1) * COAP_TICKS_PER_SECOND;
                if (now < refresh_at) {
                    coap_tick_t ms = (refresh_at - now) * 1000 / COAP_TICKS_PER_SECOND;
                    if (timeout == COAP_IO_WAIT || ms < timeout) timeout = ms;
                }
            }

            if (interval_s > 0) {
                coap_tick_t next = last_notif_time + interval_s * COAP_TICKS_PER_SECOND;
                if (now >= next) {
                    notif_send_once(now);
                    last_notif_time = now;
                    continue;
                } else {
                    coap_tick_t ms = (next - now) * 1000 / COAP_TICKS_PER_SECOND;
                    if (timeout == COAP_IO_WAIT || ms < timeout) timeout = ms;
                }
            }
        }

        coap_io_process(uc_ctx, timeout);
    }

    coap_free_context(uc_ctx);
    coap_cleanup();
    return 0;
}
