#include <coap3/coap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include "cbor_helper.h"
#include "oscore_helper.h"

#define DEFAULT_PORT 5683
#define DEFAULT_MCAST_IP "224.0.1.187"
#define DEFAULT_MCAST_PORT 56830

static int quit = 0;
static int sensor_value = 0;
static uint32_t observe_seq = 1;

// Group token (4 bytes) matching our multicast registration setup
static const uint8_t group_token[] = {0x11, 0x22, 0x33, 0x44};
static const size_t group_token_len = sizeof(group_token);

static char mcast_ip[MAX_HOST_LEN] = DEFAULT_MCAST_IP;
static uint16_t mcast_port = DEFAULT_MCAST_PORT;

static coap_session_t *mcast_session = NULL;

/* The latest multicast notification, in the transport-independent form of Section 4.2.2:
 * the code byte, then the options, then the payload — no version/TKL, Message ID or Token.
 * draft-ietf-core-observe-multicast-notifications-15 Section 4.3 requires the server to store
 * the latest multicast notification, and a client registering later is served that very
 * message as 'last_notif' (Section 4.2). It starts as INIT_NOTIF, which is composed once and
 * never transmitted (Section 4.1 step 6), and is replaced by the bytes of each notification
 * actually sent on the wire, so the Observe Option it carries is always the one that went out. */
static uint8_t last_notif[128];
static size_t last_notif_len = 0;

/* Composes INIT_NOTIF: 2.05 | Observe 0 | Content-Format text/plain | payload.
 * The Observe Option is empty (value 0) because INIT_NOTIF is never sent and the first
 * notification on the wire carries Observe 1; the numbering is strictly increasing from there. */
static size_t build_init_notif(uint8_t *ti, size_t ti_len, const char *payload) {
    size_t plen = strlen(payload);
    size_t n = 0;

    if (ti_len < 5 + plen)
        return 0;
    ti[n++] = (uint8_t)COAP_RESPONSE_CODE(205);          /* 2.05 Content */
    ti[n++] = 0x60;                                       /* Observe, empty value = 0 */
    ti[n++] = 0x60;                                       /* Content-Format, empty value = text/plain */
    ti[n++] = 0xFF;                                       /* payload marker */
    memcpy(ti + n, payload, plen);
    return n + plen;
}

/* The transport-independent form of a multicast notification built by build_notification():
 * its code byte, then everything from the first option on. */
static size_t notification_ti(const uint8_t *udp, size_t udp_len, uint8_t *ti, size_t ti_len) {
    size_t token_off = 4 + group_token_len;               /* version/TKL, code, MID, Token */

    if (udp_len <= token_off || ti_len < 1 + (udp_len - token_off))
        return 0;
    ti[0] = udp[1];                                       /* the code byte */
    memcpy(ti + 1, udp + token_off, udp_len - token_off);
    return 1 + (udp_len - token_off);
}

// Port the server endpoint listens on; the multicast notifications are sent
// from that same endpoint, so they inherit SRV_PORT.
static uint16_t srv_port = DEFAULT_PORT;

// Cached descriptor of the server endpoint's own UDP socket (see
// server_endpoint_sock()); -1 until it is found.
static int srv_sock_fd = -1;

static void handle_sigint(int signum) {
    (void)signum;
    quit = 1;
}

static void hnd_get_obs(coap_resource_t *resource,
                         coap_session_t *session,
                         const coap_pdu_t *request,
                         const coap_string_t *query,
                         coap_pdu_t *response) {
    (void)resource;
    (void)query;

    coap_opt_iterator_t opt_iter;
    coap_opt_t *opt = coap_check_option(request, COAP_OPTION_OBSERVE, &opt_iter);

    if (opt) {
        uint32_t observe_val = coap_decode_var_bytes(coap_opt_value(opt), coap_opt_length(opt));
        if (observe_val == 0) {
            // draft-15 Section 4.2: the informative response "MUST be a Confirmable message
            // sent as a separate response" (RFC 7252 Section 5.2.2).  The first call registers
            // an async response, which makes libcoap send the empty ACK; the response is built
            // when libcoap calls the handler again, and goes out as a CON.
            coap_async_t *async = coap_find_async(session, coap_pdu_get_token(request));
            if (!async) {
                async = coap_register_async(session, request, 0);
                if (async)
                    coap_async_trigger(async);
                else
                    coap_pdu_set_code(response, COAP_RESPONSE_CODE(500));
                return;
            }
            const coap_address_t *peer_addr = coap_session_get_addr_remote(session);
            char peer_ip[MAX_HOST_LEN] = "unknown";
            uint16_t peer_port = 0;
            if (peer_addr) {
                if (peer_addr->addr.sa.sa_family == AF_INET) {
                    inet_ntop(AF_INET, &peer_addr->addr.sin.sin_addr, peer_ip, sizeof(peer_ip));
                    peer_port = ntohs(peer_addr->addr.sin.sin_port);
                } else if (peer_addr->addr.sa.sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &peer_addr->addr.sin6.sin6_addr, peer_ip, sizeof(peer_ip));
                    peer_port = ntohs(peer_addr->addr.sin6.sin6_port);
                }
            }
            printf("Received observe registration request from %s:%d\n", peer_ip, peer_port);

            // Set up informative response parameters
            tp_info_t tp;
            // Get local address
            const coap_address_t *local_addr = coap_session_get_addr_local(session);
            char local_ip[MAX_HOST_LEN] = "127.0.0.1";
            uint16_t local_port = DEFAULT_PORT;

            if (local_addr) {
                if (local_addr->addr.sa.sa_family == AF_INET) {
                    inet_ntop(AF_INET, &local_addr->addr.sin.sin_addr, local_ip, sizeof(local_ip));
                    local_port = ntohs(local_addr->addr.sin.sin_port);
                } else if (local_addr->addr.sa.sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &local_addr->addr.sin6.sin6_addr, local_ip, sizeof(local_ip));
                    local_port = ntohs(local_addr->addr.sin6.sin6_port);
                }
            }

            strncpy(tp.server_host, local_ip, MAX_HOST_LEN);
            tp.server_port = local_port;
            strncpy(tp.client_host, mcast_ip, MAX_HOST_LEN);
            tp.client_port = mcast_port;
            memcpy(tp.token, group_token, group_token_len);
            tp.token_len = group_token_len;

            // 1. Construct ph_req as a transport-independent CoAP message (Section 4.2.2):
            // [Code = 0x01 (GET)] [Options...]
            uint8_t ph_req[128];
            size_t ph_req_len = 0;
            ph_req[ph_req_len++] = 0x01; // Code: GET
            ph_req[ph_req_len++] = 0x60; // Option: Observe (delta=6, len=0)

            coap_str_const_t *uri_path = coap_resource_get_uri_path(resource);
            const char *path = uri_path ? (const char *)uri_path->s : "obs";
            size_t path_len = uri_path ? uri_path->length : 3;

            if (path_len < 13) {
                ph_req[ph_req_len++] = (5 << 4) | (path_len & 0x0F); // Uri-Path Option (delta=5, len=path_len)
            } else {
                ph_req[ph_req_len++] = (5 << 4) | 13;
                ph_req[ph_req_len++] = path_len - 13;
            }
            memcpy(&ph_req[ph_req_len], path, path_len);
            ph_req_len += path_len;

            // 2. last_notif: the latest multicast notification as stored by the server
            //    (Section 4.3) — INIT_NOTIF until the first notification has been sent,
            //    then the bytes of that notification as they went on the wire.
            if (last_notif_len == 0) {
                char init_payload[32];
                snprintf(init_payload, sizeof(init_payload), "%d", sensor_value);
                last_notif_len = build_init_notif(last_notif, sizeof(last_notif), init_payload);
            }

            uint8_t *cbor_buf = NULL;
            size_t cbor_len = 0;

            if (encode_observation_info_full(&tp, ph_req, ph_req_len, last_notif, last_notif_len, &cbor_buf, &cbor_len) == 0) {
                // Return 5.03 Service Unavailable (RFC Section 4.2)
                coap_pdu_set_code(response, COAP_RESPONSE_CODE(503));
                coap_pdu_set_type(response, COAP_MESSAGE_CON);
                
                // Add Content-Format option: 12 (application/informative-response+cbor)
                uint8_t cf_buf[4];
                size_t cf_len = coap_encode_var_safe(cf_buf, sizeof(cf_buf), 12);
                coap_add_option(response, COAP_OPTION_CONTENT_FORMAT, cf_len, cf_buf);

                // Add CBOR payload
                coap_add_data(response, cbor_len, cbor_buf);
                
                printf("Sent 5.03 Informative Response with tp_info, ph_req, and last_notif (%zu bytes CBOR)\n", cbor_len);
                free(cbor_buf);
            } else {
                coap_pdu_set_code(response, COAP_RESPONSE_CODE(500));
            }
            return;
        }
    }

    // Default response if not observing
    coap_pdu_set_code(response, COAP_RESPONSE_CODE(205));
    char payload[32];
    snprintf(payload, sizeof(payload), "%d", sensor_value);
    coap_add_data(response, strlen(payload), (const uint8_t *)payload);
}

// draft-15 §4.3: a multicast notification "MUST be sent from the same IP
// address SRV_ADDR and port number SRV_PORT where the corresponding
// informative responses are sent from by the server ... redirection MUST NOT
// be used".  A libcoap client session with an unbound local address cannot
// honour that -- the kernel picks an ephemeral source port -- so the
// notification is serialised here and written straight to the server
// endpoint's own socket, the way src/sec/sec_group.c:sec_mcast_send() does
// for the secure server.  The bytes on the wire are otherwise unchanged.
//
// This build sees only libcoap's installed public headers, which declare
// coap_endpoint_t and coap_socket_t as opaque: no public call returns the
// endpoint's socket (coap_context_get_coap_fd() is the DTLS socket, not it),
// and a second UDP socket cannot be bound to the same port (macOS returns
// EADDRINUSE even with SO_REUSEADDR, which libcoap already sets).  The
// endpoint is the one UDP socket in this process bound to srv_port, so that
// is the property used to find it.  The answer is cached and re-validated
// before every send.
static int server_endpoint_sock(void) {
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);

    if (srv_sock_fd >= 0 &&
        getsockname(srv_sock_fd, (struct sockaddr *)&local, &local_len) == 0 &&
        local.sin_family == AF_INET && ntohs(local.sin_port) == srv_port)
        return srv_sock_fd;

    srv_sock_fd = -1;
    struct rlimit rl;
    int maxfd = 256;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
        (rlim_t)maxfd < rl.rlim_cur)
        maxfd = (int)rl.rlim_cur;
    if (maxfd > 65536) maxfd = 65536;

    for (int fd = 0; fd < maxfd; fd++) {
        int type = 0;
        socklen_t type_len = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) < 0 ||
            type != SOCK_DGRAM)
            continue;
        local_len = sizeof(local);
        if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
            continue;
        if (local.sin_family != AF_INET || ntohs(local.sin_port) != srv_port)
            continue;
        srv_sock_fd = fd;
        break;
    }
    return srv_sock_fd;
}

// RFC 7252 §3.1 option encoding: the option delta and length share one header
// byte, with the 13/14/15 extended nibbles so a long Observe value still
// encodes correctly.  Returns the new offset, or -1.
static int put_option(uint8_t *buf, size_t off, size_t buflen,
                      unsigned delta, const uint8_t *val, size_t vlen) {
    unsigned d = delta, l = (unsigned)vlen;
    unsigned dn = d < 13 ? d : d < 269 ? 13 : 14;   /* nibble: value, 13 (+1 byte), 14 (+2 bytes) */
    unsigned ln = l < 13 ? l : l < 269 ? 13 : 14;
    size_t ext = (dn == 13 ? 1 : dn == 14 ? 2 : 0) + (ln == 13 ? 1 : ln == 14 ? 2 : 0);

    if (d > 65804 || l > 65804 || buflen - off < 1 + ext + vlen)
        return -1;
    buf[off++] = (uint8_t)((dn << 4) | ln);
    if (dn == 13) {
        buf[off++] = (uint8_t)(d - 13);
    } else if (dn == 14) {
        buf[off++] = (uint8_t)((d - 269) >> 8);
        buf[off++] = (uint8_t)((d - 269) & 0xFF);
    }
    if (ln == 13) {
        buf[off++] = (uint8_t)(l - 13);
    } else if (ln == 14) {
        buf[off++] = (uint8_t)((l - 269) >> 8);
        buf[off++] = (uint8_t)((l - 269) & 0xFF);
    }
    memcpy(buf + off, val, vlen);
    return (int)(off + vlen);
}

// Serialise the notification exactly as coap_pdu_init()/coap_add_token()/
// coap_add_option()/coap_add_data() used to: 4-byte header, group token,
// Observe (6) then Content-Format (12) -- the same option numbers, order and
// values, so the bytes are identical -- payload marker, payload.
static int build_notification(uint8_t *buf, size_t buflen, uint16_t mid,
                              uint32_t seq, const char *payload, size_t *out_len) {
    uint8_t obs[8];
    unsigned obs_len = coap_encode_var_safe(obs, sizeof(obs), seq);
    size_t plen = strlen(payload);
    size_t n = 0;

    if (buflen < 4 + group_token_len + 2 + sizeof(obs) + 1 + 1 + plen)
        return -1;

    // Version 1, type NON, 4-byte token
    buf[n++] = (uint8_t)((1u << 6) | ((unsigned)COAP_MESSAGE_NON << 4) |
                         (unsigned)group_token_len);
    buf[n++] = (uint8_t)COAP_RESPONSE_CODE(205);
    buf[n++] = (uint8_t)(mid >> 8);
    buf[n++] = (uint8_t)(mid & 0xff);
    memcpy(buf + n, group_token, group_token_len);
    n += group_token_len;

    // Observe option (sequence number)
    n = put_option(buf, n, buflen, COAP_OPTION_OBSERVE, obs, obs_len);
    if (n < 0)
        return -1;
    // Content-Format (text/plain = 0), encoded as an empty value
    n = put_option(buf, n, buflen,
                   COAP_OPTION_CONTENT_FORMAT - COAP_OPTION_OBSERVE, NULL, 0);
    if (n < 0)
        return -1;

    // Payload
    buf[n++] = 0xff;
    memcpy(buf + n, payload, plen);
    n += plen;

    *out_len = n;
    return 0;
}

static void send_multicast_notification(coap_context_t *ctx) {
    if (!mcast_session) {
        coap_address_t dst_addr;
        coap_address_init(&dst_addr);
        dst_addr.size = sizeof(dst_addr.addr.sin);
        dst_addr.addr.sin.sin_family = AF_INET;
        dst_addr.addr.sin.sin_port = htons(mcast_port);
        if (inet_pton(AF_INET, mcast_ip, &dst_addr.addr.sin.sin_addr) != 1) {
            fprintf(stderr, "Invalid multicast IP: %s\n", mcast_ip);
            return;
        }
        mcast_session = coap_new_client_session(ctx, NULL, &dst_addr, COAP_PROTO_UDP);
        if (!mcast_session) {
            fprintf(stderr, "Failed to create multicast session\n");
            return;
        }
    }

    // Set payload
    char payload[32];
    snprintf(payload, sizeof(payload), "%d", sensor_value);

    uint8_t udp[256];
    size_t udp_len = 0;
    if (build_notification(udp, sizeof(udp), coap_new_message_id(mcast_session),
                           observe_seq++, payload, &udp_len) != 0) {
        fprintf(stderr, "Failed to initialize PDU for multicast notification\n");
        return;
    }

    printf("Broadcasting multicast notification: state=%d sequence=%u token=0x11223344 to %s:%u\n",
           sensor_value, observe_seq - 1, mcast_ip, mcast_port);

    int fd = server_endpoint_sock();
    if (fd < 0) {
        fprintf(stderr, "Failed to find the server endpoint's socket on port %u\n",
                (unsigned)srv_port);
        return;
    }

    struct sockaddr_in to, local;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(mcast_port);
    if (inet_pton(AF_INET, mcast_ip, &to.sin_addr) != 1 ||
        !IN_MULTICAST(ntohl(to.sin_addr.s_addr))) {
        fprintf(stderr, "Invalid multicast IP: %s\n", mcast_ip);
        return;
    }

    // The endpoint is bound to INADDR_ANY:SRV_PORT, so its local address is
    // the wildcard and the outgoing interface stays the one the route picks
    // (lo0 on this host, as before); a concrete address is used when there is
    // one.  IP_MULTICAST_LOOP does not add the endpoint to the group, so the
    // server does not receive its own notifications.
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0 ||
        local.sin_family != AF_INET) {
        perror("Failed to read the server endpoint's local address");
        return;
    }
    unsigned char loop = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &local.sin_addr,
                   sizeof(local.sin_addr)) < 0 ||
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        perror("Failed to configure multicast on the server endpoint");
        return;
    }

    if (sendto(fd, udp, udp_len, 0, (struct sockaddr *)&to, sizeof(to)) !=
        (ssize_t)udp_len) {
        perror("Failed to send multicast notification");
        return;
    }

    // Section 4.3: store what was actually sent, so that a client registering later is
    // served this very notification as 'last_notif', Observe Option included.
    last_notif_len = notification_ti(udp, udp_len, last_notif, sizeof(last_notif));
}
int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *resource_path = "obs";
    int port = DEFAULT_PORT;
    int use_oscore = 0;
    int opt;

    while ((opt = getopt(argc, argv, "sp:m:g:r:")) != -1) {
        switch (opt) {
            case 's':
                use_oscore = 1;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'm':
                strncpy(mcast_ip, optarg, sizeof(mcast_ip) - 1);
                break;
            case 'g':
                mcast_port = atoi(optarg);
                break;
            case 'r':
                resource_path = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-s] [-p port] [-m mcast_ip] [-g mcast_port] [-r resource_path]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, handle_sigint);

    coap_startup();
    coap_set_log_level(COAP_LOG_DEBUG);

    // Create context
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return 1;
    }

    // Set server endpoint (unicast)
    coap_address_t bind_addr;
    coap_address_init(&bind_addr);
    bind_addr.size = sizeof(bind_addr.addr.sin);
    bind_addr.addr.sin.sin_family = AF_INET;
    bind_addr.addr.sin.sin_port = htons(port);
    bind_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;

    coap_endpoint_t *endpoint = coap_new_endpoint(ctx, &bind_addr, COAP_PROTO_UDP);
    if (!endpoint) {
        fprintf(stderr, "Failed to create CoAP endpoint on port %d\n", port);
        coap_free_context(ctx);
        return 1;
    }
    srv_port = (uint16_t)port;

    // Enable OSCORE if requested
    if (use_oscore) {
        coap_oscore_conf_t *oscore_conf = setup_oscore_conf(1);
        if (oscore_conf) {
            coap_context_oscore_server(ctx, oscore_conf);
            printf("OSCORE protection enabled on unicast endpoint.\n");
        }
    }

    // Initialize resource with configured path
    coap_resource_t *r = coap_resource_init(coap_make_str_const(resource_path), 0);
    coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_obs);
    coap_resource_set_get_observable(r, 1);
    coap_add_resource(ctx, r);

    printf("CoAP Multicast Observe Server started with resource /%s. Listening on port %d...\n", resource_path, port);

    coap_tick_t last_notify_time = 0;
    coap_ticks(&last_notify_time);

    while (!quit) {
        coap_io_process(ctx, 100);

        coap_tick_t now;
        coap_ticks(&now);

        // Periodically update sensor and broadcast multicast notifications every 5 seconds
        if (now - last_notify_time >= COAP_TICKS_PER_SECOND * 5) {
            last_notify_time = now;
            sensor_value++;
            send_multicast_notification(ctx);
        }
    }

    if (mcast_session) {
        coap_session_release(mcast_session);
    }
    coap_free_context(ctx);
    coap_cleanup();

    printf("Server shutdown clean.\n");
    return 0;
}
