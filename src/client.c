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
#define DEFAULT_HOST "127.0.0.1"

static int quit = 0;
static int mcast_setup_needed = 0;
static tp_info_t mcast_tp;

static coap_session_t *unicast_session = NULL;
static coap_session_t *mcast_session = NULL;

static void handle_sigint(int signum) {
    (void)signum;
    quit = 1;
}

static coap_response_t hnd_response(coap_session_t *session,
                                    const coap_pdu_t *sent,
                                    const coap_pdu_t *received,
                                    const coap_mid_t id) {
    (void)session;
    (void)sent;
    (void)id;

    coap_pdu_code_t code = coap_pdu_get_code(received);
    printf("Received CoAP Response: Code %d.%02d\n", code >> 5, code & 0x1F);

    // Retrieve payload
    size_t len;
    const uint8_t *data;
    if (coap_get_data(received, &len, &data) == 0) {
        data = NULL;
        len = 0;
    }

    // Check for Informative Response: 5.03 Service Unavailable + Content-Format 120
    coap_opt_iterator_t opt_iter;
    coap_opt_t *cf_opt = coap_check_option(received, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
    uint32_t cf = 0;
    if (cf_opt) {
        cf = coap_decode_var_bytes(coap_opt_value(cf_opt), coap_opt_length(cf_opt));
    }

    if (code == COAP_RESPONSE_CODE(503) && (cf == 12 || cf == 120)) {
        printf("Detected CBOR Informative Response (ObservationInfo).\n");
        if (decode_observation_info(data, len, &mcast_tp) == 0) {
            printf("Decoded tp_info successfully:\n");
            printf("  Server Address:    %s:%d\n", mcast_tp.server_host, mcast_tp.server_port);
            printf("  Multicast Address: %s:%d\n", mcast_tp.client_host, mcast_tp.client_port);
            printf("  Group Token:       0x");
            for (size_t i = 0; i < mcast_tp.token_len; i++) {
                printf("%02X", mcast_tp.token[i]);
            }
            printf("\n");

            // Signal main thread to configure multicast endpoint
            mcast_setup_needed = 1;
        } else {
            fprintf(stderr, "Failed to decode CBOR ObservationInfo payload.\n");
        }
        return COAP_RESPONSE_OK;
    }

    // Check for group observation cancellation (5.03 with no Observe and no payload)
    if (code == COAP_RESPONSE_CODE(503) && len == 0) {
        printf("Received group observation cancellation from server. Shutting down.\n");
        quit = 1;
        return COAP_RESPONSE_OK;
    }

    // Check for multicast notification (2.05 Content)
    if (code == COAP_RESPONSE_CODE(205)) {
        coap_opt_t *obs_opt = coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter);
        uint32_t obs_seq = 0;
        if (obs_opt) {
            obs_seq = coap_decode_var_bytes(coap_opt_value(obs_opt), coap_opt_length(obs_opt));
        }

        // Print payload
        char *payload_str = malloc(len + 1);
        if (payload_str) {
            memcpy(payload_str, data, len);
            payload_str[len] = '\0';
            printf("[NOTIFICATION] sequence=%u state=%s\n", obs_seq, payload_str);
            free(payload_str);
        }
    }

    return COAP_RESPONSE_OK;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    const char *resource_path = "obs";
    int use_oscore = 0;
    int opt;

    while ((opt = getopt(argc, argv, "sh:p:r:")) != -1) {
        switch (opt) {
            case 's':
                use_oscore = 1;
                break;
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'r':
                resource_path = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-s] [-h host] [-p port] [-r resource_path]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, handle_sigint);

    coap_startup();
    coap_set_log_level(COAP_LOG_DEBUG);

    // Create CoAP context
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return 1;
    }

    // Set response handler
    coap_register_response_handler(ctx, hnd_response);

    // Resolve server address
    coap_address_t srv_addr;
    coap_address_init(&srv_addr);
    srv_addr.size = sizeof(srv_addr.addr.sin);
    srv_addr.addr.sin.sin_family = AF_INET;
    srv_addr.addr.sin.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &srv_addr.addr.sin.sin_addr) != 1) {
        fprintf(stderr, "Invalid server host IP: %s\n", host);
        coap_free_context(ctx);
        return 1;
    }

    // Connect to server (unicast)
    if (use_oscore) {
        coap_oscore_conf_t *oscore_conf = setup_oscore_conf(0);
        if (!oscore_conf) {
            coap_free_context(ctx);
            return 1;
        }
        unicast_session = coap_new_client_session_oscore(ctx, NULL, &srv_addr, COAP_PROTO_UDP, oscore_conf);
        printf("OSCORE session configured for unicast.\n");
    } else {
        unicast_session = coap_new_client_session(ctx, NULL, &srv_addr, COAP_PROTO_UDP);
    }

    if (!unicast_session) {
        fprintf(stderr, "Failed to create unicast session to %s:%d\n", host, port);
        coap_free_context(ctx);
        return 1;
    }

    // Send GET request to /obs with Observe=0 option
    coap_pdu_t *pdu = coap_new_pdu(COAP_MESSAGE_CON, (coap_pdu_code_t)COAP_REQUEST_GET, unicast_session);
    if (!pdu) {
        fprintf(stderr, "Failed to create GET request PDU\n");
        coap_session_release(unicast_session);
        coap_free_context(ctx);
        return 1;
    }

    // Set a random client token (8 bytes)
    uint8_t client_token[8];
    coap_prng(client_token, sizeof(client_token));
    coap_add_token(pdu, sizeof(client_token), client_token);

    // Add Observe option (value 0 to register)
    uint8_t obs_buf[2];
    size_t obs_len = coap_encode_var_safe(obs_buf, sizeof(obs_buf), 0);
    coap_add_option(pdu, COAP_OPTION_OBSERVE, obs_len, obs_buf);

    // Add Uri-Path option: resource_path
    coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(resource_path), (const uint8_t *)resource_path);

    printf("Sending unicast registration GET request to coap://%s:%d/%s (Observe=0)...\n", host, port, resource_path);
    if (coap_send(unicast_session, pdu) == COAP_INVALID_MID) {
        fprintf(stderr, "Failed to send registration GET request\n");
        coap_session_release(unicast_session);
        coap_free_context(ctx);
        return 1;
    }

    // Main event loop
    while (!quit) {
        coap_io_process(ctx, 100);

        // Perform multicast endpoint setup once informative response is processed
        if (mcast_setup_needed) {
            mcast_setup_needed = 0;

            printf("Closing unicast registration session...\n");
            coap_session_release(unicast_session);
            unicast_session = NULL;

            // 1. Create a local endpoint bound to the multicast port
            coap_address_t mcast_bind_addr;
            coap_address_init(&mcast_bind_addr);
            mcast_bind_addr.size = sizeof(mcast_bind_addr.addr.sin);
            mcast_bind_addr.addr.sin.sin_family = AF_INET;
            mcast_bind_addr.addr.sin.sin_port = htons(mcast_tp.client_port);
            mcast_bind_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;

            coap_endpoint_t *mcast_ep = coap_new_endpoint(ctx, &mcast_bind_addr, COAP_PROTO_UDP);
            if (!mcast_ep) {
                fprintf(stderr, "Failed to create endpoint bound to multicast port %d\n", mcast_tp.client_port);
                quit = 1;
                break;
            }

            // 2. Join the multicast group on the endpoint
            printf("Joining multicast group %s...\n", mcast_tp.client_host);
            if (coap_join_mcast_group_intf(ctx, mcast_tp.client_host, NULL) < 0) {
                fprintf(stderr, "Failed to join multicast group %s\n", mcast_tp.client_host);
                quit = 1;
                break;
            }

            // 3. Open a multicast session to mapping target
            coap_address_t mcast_dest;
            coap_address_init(&mcast_dest);
            mcast_dest.size = sizeof(mcast_dest.addr.sin);
            mcast_dest.addr.sin.sin_family = AF_INET;
            mcast_dest.addr.sin.sin_port = htons(mcast_tp.client_port);
            inet_pton(AF_INET, mcast_tp.client_host, &mcast_dest.addr.sin.sin_addr);

            mcast_session = coap_new_client_session(ctx, NULL, &mcast_dest, COAP_PROTO_UDP);
            if (!mcast_session) {
                fprintf(stderr, "Failed to establish multicast session\n");
                quit = 1;
                break;
            }

            // 4. Inject a phantom request to let libcoap register and track the group Token
            coap_pdu_t *phantom_pdu = coap_new_pdu(COAP_MESSAGE_NON, (coap_pdu_code_t)COAP_REQUEST_GET, mcast_session);
            if (!phantom_pdu) {
                fprintf(stderr, "Failed to create phantom PDU\n");
                quit = 1;
                break;
            }

            // Add group Token
            coap_add_token(phantom_pdu, mcast_tp.token_len, mcast_tp.token);

            // Add Observe option
            coap_add_option(phantom_pdu, COAP_OPTION_OBSERVE, obs_len, obs_buf);

            // Add Uri-Path option: resource_path
            coap_add_option(phantom_pdu, COAP_OPTION_URI_PATH, strlen(resource_path), (const uint8_t *)resource_path);

            printf("Injecting phantom observe request with token 0x");
            for (size_t i = 0; i < mcast_tp.token_len; i++) {
                printf("%02X", mcast_tp.token[i]);
            }
            printf(" on multicast session.\n");

            if (coap_send(mcast_session, phantom_pdu) == COAP_INVALID_MID) {
                fprintf(stderr, "Failed to send phantom request\n");
            }

            printf("Client is now listening for multicast notifications...\n");
        }
    }

    if (unicast_session) {
        coap_session_release(unicast_session);
    }
    if (mcast_session) {
        coap_session_release(mcast_session);
    }
    coap_free_context(ctx);
    coap_cleanup();

    printf("Client shutdown clean.\n");
    return 0;
}
