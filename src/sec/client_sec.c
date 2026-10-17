#include <coap3/coap.h>
#include <coap3/coap_internal.h>
#include "sec_config.h"
#include "sec_debug.h"
#include "sec_ir.h"
#include "sec_state.h"
#include "sec_group.h"
#include "sec_ti.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#endif

sec_config_t conf;
sec_cli_gobs_t gobs;
static coap_context_t *grp_ctx;
static coap_context_t *mc_ctx;
const char *compat_list = "none";
char srv_ip[64] = "127.0.0.1";
uint16_t srv_port = 5683;
char ifname[64] = "";
int client_running = 1;
int client_exit_code = 0;

static int compat_enabled(const char *name) {
    size_t n = strlen(name);
    const char *p = compat_list;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && memcmp(p, name, n) == 0) return 1;
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void unhex(const char *hex, uint8_t *buf, size_t max_len) {
    size_t i = 0;
    while (*hex && *(hex+1) && i < max_len) {
        sscanf(hex, "%2hhx", &buf[i++]);
        hex += 2;
    }
}

/* Raw receive context, wildcard GRP_PORT, reusable by clients
 * on the same host. The pinned fork has no socket-setup callback and sets
 * only SO_REUSEADDR. Adopt a socket with both options set BEFORE bind
 * (required on macOS), retaining libcoap's endpoint and receive handler. */
static int join_notifications(const char *group, uint16_t port) {
    struct in_addr group_addr;
    if (inet_pton(AF_INET, group, &group_addr) != 1 ||
        !IN_MULTICAST(ntohl(group_addr.s_addr)) || !port) return 0;

    coap_address_t addr;
    coap_address_init(&addr);
    addr.size = sizeof(addr.addr.sin);
    addr.addr.sin.sin_family = AF_INET;
    addr.addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
    /* Allocate the endpoint on an unused port before adopting our socket. */
    coap_endpoint_t *ep = coap_new_endpoint(mc_ctx, &addr, COAP_PROTO_UDP);
    if (!ep) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int on = 1;
    if (fd < 0) goto fail;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0 ||
        ioctl(fd, FIONBIO, &on) < 0) goto fail;
    /* libcoap needs destination metadata on a wildcard endpoint. */
#ifdef IP_PKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) goto fail;
#else
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) < 0) goto fail;
#endif
    addr.addr.sin.sin_port = htons(port);
    if (bind(fd, &addr.addr.sa, addr.size) < 0) goto fail;

    coap_socket_dgrm_close(&ep->sock);
    ep->sock.fd = fd;
    ep->sock.endpoint = ep;
    ep->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND | COAP_SOCKET_WANT_READ;
    ep->bind_addr = addr;
#ifdef COAP_EPOLL_SUPPORT
    coap_epoll_ctl_add(&ep->sock, EPOLLIN, __func__);
#endif
    /* MO-15 §5.2 step 1: group is decoded tpi_client; -I is an interface. */
    if (coap_join_mcast_group_intf(mc_ctx, group, ifname[0] ? ifname : NULL) < 0) {
        coap_free_endpoint(ep);
        return 0;
    }
    return 1;
fail:
    perror("multicast receive socket");
    if (fd >= 0) close(fd);
    coap_free_endpoint(ep);
    return 0;
}

static coap_response_t hnd_notif(coap_session_t *session, const coap_pdu_t *sent, const coap_pdu_t *received, const coap_mid_t id) {
    if (sent) return COAP_RESPONSE_OK;
    if (!gobs.tuple_valid) return COAP_RESPONSE_OK;
    coap_bin_const_t token = coap_pdu_get_token(received);
    if (token.length != gobs.token_len || memcmp(token.s, gobs.token, token.length) != 0) {
        return COAP_RESPONSE_OK;
    }

    char src_ip[64];
    coap_address_t *rem = &session->addr_info.remote;
    if (rem->addr.sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &rem->addr.sin.sin_addr, src_ip, sizeof(src_ip));
    } else {
        src_ip[0] = 0;
    }
    uint16_t src_port = ntohs(rem->addr.sin.sin_port);

    int port_ok = (src_port == gobs.srv_port);
    if (compat_list && strstr(compat_list, "java-any-srcport")) {
        port_ok = 1;
    }
    int ip_ok = (strcmp(src_ip, gobs.srv_addr) == 0);

    if (!ip_ok || !port_ok) {
        printf("[SEC-REJECT] NOTIF: source %s:%u != %s:%u\n", src_ip, src_port, gobs.srv_addr, gobs.srv_port);
        return COAP_RESPONSE_OK;
    }

    coap_pdu_code_t code = coap_pdu_get_code(received);
    int code_ok = (code == COAP_RESPONSE_CODE(205));
    if (compat_list && strstr(compat_list, "java-code204-notif")) {
        if (code == COAP_RESPONSE_CODE(204)) code_ok = 1;
    }
    if (!code_ok) {
        printf("[SEC-REJECT] NOTIF: outer code %d.%02d\n", code >> 5, code & 0x1F);
        return COAP_RESPONSE_OK;
    }

    uint64_t piv = 0;
    uint8_t pt[256];
    size_t ptlen;
    sec_grp_t grp;
    grp.ctx = grp_ctx;

    unsigned compat = 0;
    if (compat_list && strstr(compat_list, "java-phreq-empty-option")) compat |= 1;

    if (sec_notif_verify(&grp, &gobs.tuple, (coap_pdu_t *)received, compat, &piv, pt, &ptlen)) {
        if (sec_cli_accept(&gobs, piv)) {
            uint8_t iudp[1024];
            iudp[0] = 0x50;
            iudp[1] = pt[0];
            iudp[2] = iudp[3] = 0;
            memcpy(iudp + 4, pt + 1, ptlen - 1);
            coap_pdu_t *inner = coap_pdu_init(0, 0, 0, sizeof(iudp));
            if (coap_pdu_parse(COAP_PROTO_UDP, iudp, ptlen + 3, inner)) {
                size_t dlen;
                const uint8_t *data;
                if (coap_get_data(inner, &dlen, &data) && dlen > 0) {
                    snprintf(gobs.last_value, sizeof(gobs.last_value), "%.*s", (int)dlen, data);
                }
            }
            coap_delete_pdu(inner);

            unsigned outer_obs = 1;
            coap_opt_iterator_t oi;
            coap_opt_t *obs = coap_check_option(received, COAP_OPTION_OBSERVE, &oi);
            if (obs) outer_obs = coap_decode_var_bytes(coap_opt_value(obs), coap_opt_length(obs));

            printf("[NOTIFICATION] sequence=%u state=%s piv=%02x\n", outer_obs, gobs.last_value, (unsigned)piv);
        }
    } else {
        printf("[SEC-REJECT] NOTIF: verification failed\n");
    }
    return COAP_RESPONSE_OK;
}

static coap_response_t hnd_ir(coap_session_t *session,
                              const coap_pdu_t *sent,
                              const coap_pdu_t *received,
                              const coap_mid_t id) {
    (void)session; (void)sent; (void)id;

    coap_pdu_code_t rcvd_code = coap_pdu_get_code(received);
    if (rcvd_code == COAP_RESPONSE_CODE(503)) {
        sec_dbg_pdu("RX PLAIN", "server", received);
        coap_opt_iterator_t oi;
        coap_opt_t *cf = coap_check_option(received, COAP_OPTION_CONTENT_FORMAT, &oi);
        if (!cf || coap_decode_var_bytes(coap_opt_value(cf), coap_opt_length(cf)) != 12) {
            printf("[SEC-REJECT] IR: invalid Content-Format\n");
            client_exit_code = 3;
            client_running = 0;
            return COAP_RESPONSE_OK;
        }
        size_t len;
        const uint8_t *data;
        if (coap_get_data(received, &len, &data)) {
            sec_dbg_bytes("RX PLAIN IR", data, len);
            tp_info_t tp = {0};
            const uint8_t *ph = NULL, *ln = NULL;
            size_t ph_len = 0, ln_len = 0;

            if (sec_ir_decode(data, len, &tp, &ph, &ph_len, &ln, &ln_len) == 0) {
                char tok_str[64] = "none";
                coap_bin_const_t req_tok = coap_pdu_get_token(received);
                if (req_tok.length > 0) {
                    for (size_t i = 0; i < req_tok.length; i++) {
                        sprintf(&tok_str[i*2], "%02x", req_tok.s[i]);
                    }
                }

                printf("[IR] code=5.03 cf=12 tpi_server=%s:%u grp=%s:%u token=%s ph_req=%zuB last_notif=%zuB\n",
                       tp.server_host, tp.server_port,
                       tp.client_host, tp.client_port,
                       tok_str, ph_len, ln_len);

                if (ph_len == 0) {
                    /* R9.9.3.1.1: ph_req absent → malformed IR, withdraw */
                    printf("[SEC-REJECT] IR: missing ph_req\n");
                    client_exit_code = 3;
                    client_running = 0;
                    return COAP_RESPONSE_OK;
                }

                /* verify ph_req */
                sec_grp_t grp = { grp_ctx };
                unsigned compat = (compat_enabled("java-udp-phreq") ? 1u : 0u) |
                                  (compat_enabled("java-empty-phreq-aad") ? 2u : 0u);
                sec_tuple_t verified;
                if (sec_phantom_verify(&grp, ph, ph_len, tp.token, tp.token_len, conf.resource, compat, &verified) &&
                    sec_cli_gobs_bind(&gobs, &verified, tp.token, tp.token_len,
                                      tp.server_host, tp.server_port,
                                      tp.client_host, tp.client_port)) {
                    if ((compat & 1u) && (ph[0] & 0xc0) == 0x40)
                        printf("[COMPAT] java-udp-phreq: stripped verified UDP wrapper\n");
                    if (compat & 2u)
                        printf("[COMPAT] java-empty-phreq-aad: verified with empty OSCORE option in AAD\n");
                    printf("[PH_REQ] verified kid=");
                    print_hex(verified.kid, verified.kid_len);
                    printf(" piv=");
                    print_hex(verified.piv, verified.piv_len);
                    printf(" gid=");
                    print_hex(verified.kid_ctx, verified.kid_ctx_len);
                    printf(" replay_check=skipped window=unchanged\n");

                    if (ln_len > 0) {
                        coap_pdu_t *pdu = NULL;
                        if (sec_ti_import(ln, ln_len, tp.token, tp.token_len, 0, compat, &pdu)) {
                            uint64_t rpiv;
                            uint8_t pt[256];
                            size_t ptlen;
                            if (sec_notif_verify(&grp, &verified, pdu, compat, &rpiv, pt, &ptlen)) {
                                if (sec_cli_accept(&gobs, rpiv)) {
                                    unsigned outer_obs = 1;
                                    coap_opt_iterator_t oi;
                                    coap_opt_t *obs = coap_check_option(pdu, COAP_OPTION_OBSERVE, &oi);
                                    if (obs) outer_obs = coap_decode_var_bytes(coap_opt_value(obs), coap_opt_length(obs));

                                    uint8_t iudp[1024];
                                    iudp[0] = 0x50;
                                    iudp[1] = pt[0];
                                    iudp[2] = iudp[3] = 0;
                                    memcpy(iudp + 4, pt + 1, ptlen - 1);
                                    coap_pdu_t *inner = coap_pdu_init(0, 0, 0, sizeof(iudp));
                                    if (coap_pdu_parse(COAP_PROTO_UDP, iudp, ptlen + 3, inner)) {
                                        size_t dlen;
                                        const uint8_t *data;
                                        if (coap_get_data(inner, &dlen, &data) && dlen > 0) {
                                            snprintf(gobs.last_value, sizeof(gobs.last_value), "%.*s", (int)dlen, data);
                                        }
                                    }
                                    coap_delete_pdu(inner);
                                    gobs.last_observe = outer_obs;
                                    printf("[LAST_NOTIF] state=%s observe=%u piv=%02x\n", gobs.last_value, outer_obs, (unsigned)rpiv);
                                }
                            }
                            coap_delete_pdu(pdu);
                        }
                    }

                    if (!mc_ctx->endpoint && !join_notifications(tp.client_host, tp.client_port)) {
                        printf("[SEC-REJECT] IR: group endpoint setup failed\n");
                        sec_cli_gobs_clear(&gobs);
                        client_exit_code = 3;
                        client_running = 0;
                    }
                    /* Client keeps running to listen for notifications */
                } else {
                    printf("[SEC-REJECT] IR: ph_req verification failed\n");
                    sec_cli_gobs_clear(&gobs);
                    client_exit_code = 3;
                    client_running = 0;
                }
            } else {
                printf("[SEC-REJECT] IR: malformed CBOR\n");
                client_exit_code = 3;
                client_running = 0;
            }
        } else {
            printf("[SEC-REJECT] IR: missing payload\n");
            client_exit_code = 3;
            client_running = 0;
        }
    } else {
        // Empty ACK or other
        if (coap_pdu_get_type(received) == COAP_MESSAGE_ACK && rcvd_code == 0) {
            // just wait for the separate CON
            return COAP_RESPONSE_OK;
        }
        client_running = 0;
    }
    return COAP_RESPONSE_OK;
}

int main(int argc, char **argv) {
    setlinebuf(stdout);
    int opt;
    char conf_path[256] = "";
    while ((opt = getopt(argc, argv, "c:h:p:I:d:C:")) != -1) {
        switch (opt) {
            case 'c': snprintf(conf_path, sizeof(conf_path), "%s", optarg); break;
            case 'h': snprintf(srv_ip, sizeof(srv_ip), "%s", optarg); break;
            case 'p': srv_port = atoi(optarg); break;
            case 'I': snprintf(ifname, sizeof(ifname), "%s", optarg); break;
            case 'd': sec_debug_level = atoi(optarg); break;
            case 'C': compat_list = optarg; break;
            default: exit(1);
        }
    }

    if (!conf_path[0] || sec_config_load(conf_path, &conf) < 0) {
        fprintf(stderr, "Failed to load config\n");
        exit(1);
    }

    if (conf.is_server) exit(1);

    printf("[SEC] coap_client_sec profile=%s config=%s compat=%s debug=%d\n",
           conf.profile_name, conf_path, compat_list, sec_debug_level);

    coap_startup();
    sec_dbg_init(sec_debug_level);
    coap_context_t *uc_ctx = coap_new_context(NULL);
    if (!uc_ctx) exit(2);

    coap_register_response_handler(uc_ctx, hnd_ir);

    char buf[2048];
    if (sec_conf_pairwise_text(&conf, 0, buf, sizeof(buf)) != 0) exit(2);

    coap_str_const_t osc_conf = { strlen(buf), (const uint8_t *)buf };
    coap_oscore_conf_t *oc = coap_new_oscore_conf(osc_conf, NULL, NULL, conf.pairwise_client.start_sn);
    if (!oc) exit(2);

    /* Crypto-only context; network responses arrive raw on mc_ctx. */
    char gbuf[2048];
    if (sec_conf_group_text(&conf, gbuf, sizeof(gbuf)) != 0) exit(2);
    coap_str_const_t g_osc_conf = { strlen(gbuf), (const uint8_t *)gbuf };
    coap_oscore_conf_t *goc = coap_new_oscore_conf(g_osc_conf, NULL, NULL, conf.group_start_sn);
    grp_ctx = coap_new_context(NULL);
    if (!grp_ctx || !goc || !coap_context_oscore_server(grp_ctx, goc)) exit(2);
    mc_ctx = coap_new_context(NULL);
    if (!mc_ctx) exit(2);
    /* Accept option 9 as understood; hnd_notif performs the verification.
     * No OSCORE context or request association belongs on this socket. */
    coap_register_option(mc_ctx, COAP_OPTION_OSCORE);
    coap_register_response_handler(mc_ctx, hnd_notif);
    /* GO-28 §2.6.1: group Recipient Contexts start with valid replay windows.
     * The fork's default Echo bootstrap state leaves ordinary first requests
     * unchecked; only ph_req uses the scoped §9.3.1 replay exception. */
    for (oscore_recipient_ctx_t *rc = grp_ctx->p_osc_ctx->recipient_chain;
         rc; rc = rc->next_recipient) {
        rc->initial_state = 0;
    }

    coap_address_t srv_addr;
    coap_address_init(&srv_addr);
    srv_addr.addr.sin.sin_family = AF_INET;
    srv_addr.addr.sin.sin_port = htons(srv_port);
    inet_pton(AF_INET, srv_ip, &srv_addr.addr.sin.sin_addr);
    srv_addr.size = sizeof(srv_addr.addr.sin);

    coap_session_t *session = coap_new_client_session_oscore(uc_ctx, NULL, &srv_addr, COAP_PROTO_UDP, oc);
    if (!session) exit(2);

    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, coap_new_message_id(session), coap_session_max_pdu_size(session));

    uint8_t token[8];
    unhex(conf.token, token, 8); // token is random, let's just use what's in conf
    if (strlen(conf.token) > 0 && strcmp(conf.token, "random") != 0) {
        coap_add_token(pdu, strlen(conf.token)/2, token);
    } else {
        uint32_t t;
        coap_prng((uint8_t*)&t, 4);
        coap_add_token(pdu, 4, (uint8_t*)&t);
    }

    coap_add_option(pdu, COAP_OPTION_OBSERVE, 0, NULL);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(conf.resource), (const uint8_t *)conf.resource);

    sec_dbg_pdu("TX PLAIN", srv_ip, pdu);
    if (coap_send(session, pdu) == COAP_INVALID_MID) exit(2);

    while (client_running) {
        coap_io_process(uc_ctx, 100);
        if (client_running && gobs.tuple_valid)
            coap_io_process(mc_ctx, 1);
    }

    sec_cli_gobs_clear(&gobs);
    coap_free_context(mc_ctx);
    coap_free_context(grp_ctx);
    coap_free_context(uc_ctx);
    coap_cleanup();
    return client_exit_code;
}
