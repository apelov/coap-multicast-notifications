#include "cbor_helper.h"
#include <cbor.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SCHEME_COAP -1
#define DEFAULT_COAP_PORT 5683

/* Helper to build a CRI-no-local array matching Java format: [ scheme-id, [ host-ip-bytes, ?port ] ] */
static cbor_item_t *build_cri(const char *host_str, uint16_t port) {
    cbor_item_t *cri = cbor_new_definite_array(2);
    if (!cri) return NULL;

    // 1. scheme-id = -1
    cbor_item_t *scheme = cbor_new_int8();
    if (!scheme) {
        cbor_decref(&cri);
        return NULL;
    }
    cbor_mark_negint(scheme);
    cbor_set_uint8(scheme, 0); // represents -1
    if (cbor_array_push(cri, cbor_move(scheme)) == false) {
        cbor_decref(&cri);
        return NULL;
    }

    // 2. authority array = [ host-ip-bytes, ?port ]
    struct in_addr ipv4;
    int is_ipv4 = inet_pton(AF_INET, host_str, &ipv4);
    size_t host_len = is_ipv4 ? 4 : 16;
    uint8_t host_bytes[16];

    if (is_ipv4) {
        memcpy(host_bytes, &ipv4.s_addr, 4);
    } else {
        // Fallback or IPv6
        struct in6_addr ipv6;
        if (inet_pton(AF_INET6, host_str, &ipv6) == 1) {
            memcpy(host_bytes, &ipv6.s6_addr, 16);
        } else {
            // If it's not a valid IP, just treat it as 127.0.0.1
            ipv4.s_addr = htonl(INADDR_LOOPBACK);
            memcpy(host_bytes, &ipv4.s_addr, 4);
            host_len = 4;
        }
    }

    cbor_item_t *authority = cbor_new_definite_array(port == DEFAULT_COAP_PORT ? 1 : 2);
    if (!authority) {
        cbor_decref(&cri);
        return NULL;
    }

    cbor_item_t *host_item = cbor_build_bytestring(host_bytes, host_len);
    if (!host_item || cbor_array_push(authority, cbor_move(host_item)) == false) {
        cbor_decref(&authority);
        cbor_decref(&cri);
        return NULL;
    }

    if (port != DEFAULT_COAP_PORT) {
        cbor_item_t *port_item = cbor_build_uint16(port);
        if (!port_item || cbor_array_push(authority, cbor_move(port_item)) == false) {
            cbor_decref(&authority);
            cbor_decref(&cri);
            return NULL;
        }
    }

    if (cbor_array_push(cri, cbor_move(authority)) == false) {
        cbor_decref(&cri);
        return NULL;
    }

    return cri;
}

int encode_observation_info_full(const tp_info_t *tp,
                                 const uint8_t *ph_req, size_t ph_req_len,
                                 const uint8_t *last_notif, size_t last_notif_len,
                                 uint8_t **out_buf, size_t *out_len) {
    if (!tp || !out_buf || !out_len) return -1;

    size_t map_size = 1;
    if (ph_req && ph_req_len > 0) map_size++;
    if (last_notif && last_notif_len > 0) map_size++;

    // Root map
    cbor_item_t *root = cbor_new_definite_map(map_size);
    if (!root) return -1;

    // tp_info array: [ tpi_server, tpi_client, tpi_token ]
    cbor_item_t *tp_info = cbor_new_definite_array(3);
    if (!tp_info) {
        cbor_decref(&root);
        return -1;
    }

    // Build tpi_server
    cbor_item_t *tpi_server = build_cri(tp->server_host, tp->server_port);
    if (!tpi_server || cbor_array_push(tp_info, cbor_move(tpi_server)) == false) {
        cbor_decref(&tp_info);
        cbor_decref(&root);
        return -1;
    }

    // Build tpi_client
    cbor_item_t *tpi_client = build_cri(tp->client_host, tp->client_port);
    if (!tpi_client || cbor_array_push(tp_info, cbor_move(tpi_client)) == false) {
        cbor_decref(&tp_info);
        cbor_decref(&root);
        return -1;
    }

    // Build token
    cbor_item_t *token_item = cbor_build_bytestring(tp->token, tp->token_len);
    if (!token_item || cbor_array_push(tp_info, cbor_move(token_item)) == false) {
        cbor_decref(&tp_info);
        cbor_decref(&root);
        return -1;
    }

    // Add to map under key 0
    cbor_item_t *key0 = cbor_build_uint8(0);
    if (!key0) {
        cbor_decref(&tp_info);
        cbor_decref(&root);
        return -1;
    }
    if (cbor_map_add(root, (struct cbor_pair){.key = cbor_move(key0), .value = cbor_move(tp_info)}) == false) {
        cbor_decref(&root);
        return -1;
    }

    // Add ph_req under key 1 if present
    if (ph_req && ph_req_len > 0) {
        cbor_item_t *key1 = cbor_build_uint8(1);
        cbor_item_t *ph_val = cbor_build_bytestring(ph_req, ph_req_len);
        if (!key1 || !ph_val || cbor_map_add(root, (struct cbor_pair){.key = cbor_move(key1), .value = cbor_move(ph_val)}) == false) {
            if (key1) cbor_decref(&key1);
            if (ph_val) cbor_decref(&ph_val);
            cbor_decref(&root);
            return -1;
        }
    }

    // Add last_notif under key 2 if present
    if (last_notif && last_notif_len > 0) {
        cbor_item_t *key2 = cbor_build_uint8(2);
        cbor_item_t *ln_val = cbor_build_bytestring(last_notif, last_notif_len);
        if (!key2 || !ln_val || cbor_map_add(root, (struct cbor_pair){.key = cbor_move(key2), .value = cbor_move(ln_val)}) == false) {
            if (key2) cbor_decref(&key2);
            if (ln_val) cbor_decref(&ln_val);
            cbor_decref(&root);
            return -1;
        }
    }

    // Serialize
    if (cbor_serialize_alloc(root, out_buf, out_len) == 0) {
        cbor_decref(&root);
        return -1;
    }

    cbor_decref(&root);
    return 0;
}

int encode_observation_info(const tp_info_t *tp, uint8_t **out_buf, size_t *out_len) {
    return encode_observation_info_full(tp, NULL, 0, NULL, 0, out_buf, out_len);
}


/* Helper to parse CRI from CBOR array: [ scheme-id, authority ] */
static int parse_cri(cbor_item_t *cri_item, char *out_host, uint16_t *out_port) {
    if (!cbor_isa_array(cri_item) || cbor_array_size(cri_item) < 2) return -1;

    cbor_item_t *scheme = cbor_array_get(cri_item, 0);
    cbor_item_t *authority = cbor_array_get(cri_item, 1);

    if (!scheme || !authority || !cbor_isa_array(authority) || cbor_array_size(authority) < 1) {
        if (scheme) cbor_decref(&scheme);
        if (authority) cbor_decref(&authority);
        return -1;
    }

    // Check scheme
    int64_t scheme_id;
    if (cbor_isa_uint(scheme)) {
        scheme_id = (int64_t)cbor_get_uint64(scheme);
    } else if (cbor_isa_negint(scheme)) {
        scheme_id = -1 - (int64_t)cbor_get_uint64(scheme);
    } else {
        cbor_decref(&scheme);
        cbor_decref(&authority);
        return -1;
    }
    cbor_decref(&scheme);

    // Extract host-ip-bytes
    cbor_item_t *host_item = cbor_array_get(authority, 0);
    if (!host_item || !cbor_isa_bytestring(host_item)) {
        if (host_item) cbor_decref(&host_item);
        cbor_decref(&authority);
        return -1;
    }

    size_t host_len = cbor_bytestring_length(host_item);
    uint8_t *host_bytes = cbor_bytestring_handle(host_item);

    if (host_len == 4) {
        struct in_addr addr;
        memcpy(&addr.s_addr, host_bytes, 4);
        inet_ntop(AF_INET, &addr, out_host, MAX_HOST_LEN);
    } else if (host_len == 16) {
        struct in6_addr addr;
        memcpy(&addr.s6_addr, host_bytes, 16);
        inet_ntop(AF_INET6, &addr, out_host, MAX_HOST_LEN);
    } else {
        cbor_decref(&host_item);
        cbor_decref(&authority);
        return -1;
    }
    cbor_decref(&host_item);

    // Extract port if present, otherwise use default based on scheme
    if (cbor_array_size(authority) >= 2) {
        cbor_item_t *port_item = cbor_array_get(authority, 1);
        if (port_item && cbor_is_int(port_item)) {
            *out_port = (uint16_t)cbor_get_uint64(port_item);
        } else {
            *out_port = DEFAULT_COAP_PORT;
        }
        if (port_item) cbor_decref(&port_item);
    } else {
        *out_port = (scheme_id == -2) ? 5684 : DEFAULT_COAP_PORT;
    }

    cbor_decref(&authority);
    return 0;
}

int decode_observation_info(const uint8_t *buf, size_t buf_len, tp_info_t *out_tp) {
    if (!buf || buf_len == 0 || !out_tp) return -1;

    struct cbor_load_result result;
    cbor_item_t *parsed = cbor_load(buf, buf_len, &result);
    if (!parsed) return -1;

    if (!cbor_isa_map(parsed)) {
        cbor_decref(&parsed);
        return -1;
    }

    cbor_item_t *tp_info_arr = NULL;
    struct cbor_pair *pairs = cbor_map_handle(parsed);
    size_t map_size = cbor_map_size(parsed);

    // Look for key 0
    for (size_t i = 0; i < map_size; i++) {
        cbor_item_t *key = pairs[i].key;
        if (cbor_is_int(key) && cbor_get_uint64(key) == 0) {
            tp_info_arr = pairs[i].value;
            break;
        }
    }

    if (!tp_info_arr || !cbor_isa_array(tp_info_arr) || cbor_array_size(tp_info_arr) < 3) {
        cbor_decref(&parsed);
        return -1;
    }

    cbor_item_t *srv = cbor_array_get(tp_info_arr, 0);
    cbor_item_t *cli = cbor_array_get(tp_info_arr, 1);
    cbor_item_t *tok = cbor_array_get(tp_info_arr, 2);

    if (!srv || !cli || !tok) {
        if (srv) cbor_decref(&srv);
        if (cli) cbor_decref(&cli);
        if (tok) cbor_decref(&tok);
        cbor_decref(&parsed);
        return -1;
    }

    // Parse server
    if (parse_cri(srv, out_tp->server_host, &out_tp->server_port) != 0) {
        cbor_decref(&srv); cbor_decref(&cli); cbor_decref(&tok);
        cbor_decref(&parsed);
        return -1;
    }

    // Parse client (multicast)
    if (parse_cri(cli, out_tp->client_host, &out_tp->client_port) != 0) {
        cbor_decref(&srv); cbor_decref(&cli); cbor_decref(&tok);
        cbor_decref(&parsed);
        return -1;
    }

    // Parse token
    if (!cbor_isa_bytestring(tok)) {
        cbor_decref(&srv); cbor_decref(&cli); cbor_decref(&tok);
        cbor_decref(&parsed);
        return -1;
    }

    out_tp->token_len = cbor_bytestring_length(tok);
    if (out_tp->token_len > MAX_TOKEN_LEN) out_tp->token_len = MAX_TOKEN_LEN;
    memcpy(out_tp->token, cbor_bytestring_handle(tok), out_tp->token_len);

    cbor_decref(&srv);
    cbor_decref(&cli);
    cbor_decref(&tok);
    cbor_decref(&parsed);

    return 0;
}
