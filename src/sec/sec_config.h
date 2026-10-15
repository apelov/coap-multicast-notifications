#ifndef SEC_CONFIG_H
#define SEC_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define SEC_MAX_CLIENTS 3

typedef struct {
    char sender_id[64];
    char recipient_id[64];
    char master_secret[128];
    uint64_t start_sn;
} sec_conf_pairwise_ctx_t;

typedef struct {
    char id[64];
    char cred[1024]; /* CCS bytes in hex */
} sec_conf_group_recipient_t;

typedef struct {
    int is_server;
    char profile_name[64];
    char resource[64];
    char group_addr[64];
    uint16_t group_port;
    unsigned interval_s;
    char values[128];
    unsigned notif_max_age;
    char phantom_token[32];
    char token[32];

    /* Pairwise common */
    int pairwise_aead_alg;
    int pairwise_hkdf_alg;
    char pairwise_master_salt[128];
    int pairwise_replay_window;
    int pairwise_rfc8613_b_1_2;

    /* Server pairwise contexts (up to 3) */
    sec_conf_pairwise_ctx_t pairwise_server[SEC_MAX_CLIENTS];
    int num_pairwise_clients;

    /* Client pairwise context */
    sec_conf_pairwise_ctx_t pairwise_client;

    /* Group common */
    char group_gid[128];
    char group_master_secret[128];
    char group_master_salt[128];
    int group_aead_alg;
    int group_hkdf_alg;
    int group_alg_group_enc;
    int group_alg_signature;
    int group_alg_pairwise_key_agreement;
    int group_replay_window;
    char group_gm_cred[1024];

    /* Group sender */
    char group_sender_id[64];
    char group_sender_cred[1024];
    char group_sender_private_key[128];
    uint64_t group_start_sn;

    /* Group recipients */
    sec_conf_group_recipient_t group_recipients[SEC_MAX_CLIENTS];
    int num_group_recipients;

} sec_config_t;

int sec_config_load(const char *path, sec_config_t *out);
int sec_conf_pairwise_text(const sec_config_t *conf, int n, char *buf, size_t len);
int sec_conf_group_text(const sec_config_t *conf, char *buf, size_t len);

#endif
