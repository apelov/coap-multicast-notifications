#include "oscore_helper.h"
#include <string.h>
#include <stdio.h>

coap_oscore_conf_t *setup_oscore_conf(int is_server) {
    // Standard symmetric context configuration matching the Java reference setup.
    // In OSCORE: the server's sender_id matches the client's recipient_id, and vice versa.
    const char *oscore_conf_str;
    if (is_server) {
        oscore_conf_str =
            "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
            "master_salt,hex,\"9e7ca92223786340\"\n"
            "sender_id,hex,\"02\"\n"
            "recipient_id,hex,\"01\"\n"
            "replay_window,integer,32\n";
    } else {
        oscore_conf_str =
            "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
            "master_salt,hex,\"9e7ca92223786340\"\n"
            "sender_id,hex,\"01\"\n"
            "recipient_id,hex,\"02\"\n"
            "replay_window,integer,32\n";
    }

    coap_str_const_t conf_mem = {
        .length = strlen(oscore_conf_str),
        .s = (const uint8_t *)oscore_conf_str
    };

    coap_oscore_conf_t *conf = coap_new_oscore_conf(conf_mem, NULL, NULL, 0);
    if (!conf) {
        fprintf(stderr, "Failed to create OSCORE configuration via libcoap\n");
        return NULL;
    }

    return conf;
}
