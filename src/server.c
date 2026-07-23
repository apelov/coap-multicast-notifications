#include <coap3/coap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
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

            uint8_t *cbor_buf = NULL;
            size_t cbor_len = 0;

            if (encode_observation_info(&tp, &cbor_buf, &cbor_len) == 0) {
                // Return 5.03 Service Unavailable (RFC Section 4.2)
                coap_pdu_set_code(response, COAP_RESPONSE_CODE(503));
                
                // Add Content-Format option: 120 (application/informative-response+cbor)
                uint8_t cf_buf[4];
                size_t cf_len = coap_encode_var_safe(cf_buf, sizeof(cf_buf), 120);
                coap_add_option(response, COAP_OPTION_CONTENT_FORMAT, cf_len, cf_buf);

                // Add CBOR payload
                coap_add_data(response, cbor_len, cbor_buf);
                
                printf("Sent 5.03 Informative Response with tp_info (%zu bytes CBOR)\n", cbor_len);
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

    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(205),
                                    coap_new_message_id(mcast_session), 256);
    if (!pdu) {
        fprintf(stderr, "Failed to initialize PDU for multicast notification\n");
        return;
    }

    // Set group token
    if (coap_add_token(pdu, group_token_len, group_token) == 0) {
        fprintf(stderr, "Failed to add token to notification PDU\n");
        coap_delete_pdu(pdu);
        return;
    }

    // Set Observe option (sequence number)
    uint8_t obs_buf[4];
    size_t obs_len = coap_encode_var_safe(obs_buf, sizeof(obs_buf), observe_seq++);
    coap_add_option(pdu, COAP_OPTION_OBSERVE, obs_len, obs_buf);

    // Set Content-Format option (text/plain = 0)
    uint8_t cf_buf[4];
    size_t cf_len = coap_encode_var_safe(cf_buf, sizeof(cf_buf), COAP_MEDIATYPE_TEXT_PLAIN);
    coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT, cf_len, cf_buf);

    // Set payload
    char payload[32];
    snprintf(payload, sizeof(payload), "%d", sensor_value);
    coap_add_data(pdu, strlen(payload), (const uint8_t *)payload);

    printf("Broadcasting multicast notification: state=%d sequence=%u token=0x11223344 to %s:%u\n",
           sensor_value, observe_seq - 1, mcast_ip, mcast_port);

    if (coap_send(mcast_session, pdu) == COAP_INVALID_MID) {
        fprintf(stderr, "Failed to send multicast notification\n");
    }
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
