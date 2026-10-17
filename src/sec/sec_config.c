#include "sec_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

int sec_config_load(const char *path, sec_config_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    memset(out, 0, sizeof(*out));

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) {
            fclose(f);
            return -1;
        }
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        while(*key == ' ' || *key == '\t') key++;
        while(*val == ' ' || *val == '\t') val++;
        char *end = key + strlen(key) - 1;
        while(end > key && (*end == ' ' || *end == '\t')) *end-- = '\0';
        end = val + strlen(val) - 1;
        while(end > val && (*end == ' ' || *end == '\t')) *end-- = '\0';

        if (strcmp(key, "role") == 0) {
            if (strcmp(val, "server") == 0) out->is_server = 1;
            else if (strcmp(val, "client") == 0) out->is_server = 0;
            else { fclose(f); return -1; }
        } else if (strcmp(key, "profile_name") == 0) {
            snprintf(out->profile_name, sizeof(out->profile_name), "%s", val);
        } else if (strcmp(key, "label") == 0) {
            // just ignore or store it. Let's ignore it, it's just for display if we want.
        } else if (strcmp(key, "resource") == 0) {
            snprintf(out->resource, sizeof(out->resource), "%s", val);
        } else if (strcmp(key, "group_addr") == 0) {
            snprintf(out->group_addr, sizeof(out->group_addr), "%s", val);
        } else if (strcmp(key, "group_port") == 0) {
            out->group_port = atoi(val);
        } else if (strcmp(key, "interval_s") == 0) {
            out->interval_s = atoi(val);
        } else if (strcmp(key, "values") == 0) {
            snprintf(out->values, sizeof(out->values), "%s", val);
        } else if (strcmp(key, "notif_max_age") == 0) {
            out->notif_max_age = atoi(val);
        } else if (strcmp(key, "phantom_token") == 0) {
            snprintf(out->phantom_token, sizeof(out->phantom_token), "%s", val);
        } else if (strcmp(key, "token") == 0) {
            snprintf(out->token, sizeof(out->token), "%s", val);
        } else if (strcmp(key, "pairwise.aead_alg") == 0) {
            out->pairwise_aead_alg = atoi(val);
        } else if (strcmp(key, "pairwise.hkdf_alg") == 0) {
            out->pairwise_hkdf_alg = atoi(val);
        } else if (strcmp(key, "pairwise.master_salt") == 0) {
            snprintf(out->pairwise_master_salt, sizeof(out->pairwise_master_salt), "%s", val);
        } else if (strcmp(key, "pairwise.replay_window") == 0) {
            out->pairwise_replay_window = atoi(val);
        } else if (strcmp(key, "pairwise.rfc8613_b_1_2") == 0) {
            out->pairwise_rfc8613_b_1_2 = (strcmp(val, "true") == 0) ? 1 : 0;
        } else if (strncmp(key, "pairwise.", 9) == 0 && key[9] >= '1' && key[9] <= '3' && key[10] == '.') {
            int n = key[9] - '1';
            const char *sub = key + 11;
            if (n >= out->num_pairwise_clients) out->num_pairwise_clients = n + 1;
            if (strcmp(sub, "sender_id") == 0) {
                snprintf(out->pairwise_server[n].sender_id, sizeof(out->pairwise_server[n].sender_id), "%s", val);
            } else if (strcmp(sub, "recipient_id") == 0) {
                snprintf(out->pairwise_server[n].recipient_id, sizeof(out->pairwise_server[n].recipient_id), "%s", val);
            } else if (strcmp(sub, "master_secret") == 0) {
                snprintf(out->pairwise_server[n].master_secret, sizeof(out->pairwise_server[n].master_secret), "%s", val);
            } else if (strcmp(sub, "start_sn") == 0) {
                out->pairwise_server[n].start_sn = strtoull(val, NULL, 10);
            } else { fclose(f); return -1; }
        } else if (strncmp(key, "pairwise.", 9) == 0 && key[9] >= 'a' && key[9] <= 'z') {
            const char *sub = key + 9;
            if (strcmp(sub, "sender_id") == 0) {
                snprintf(out->pairwise_client.sender_id, sizeof(out->pairwise_client.sender_id), "%s", val);
            } else if (strcmp(sub, "recipient_id") == 0) {
                snprintf(out->pairwise_client.recipient_id, sizeof(out->pairwise_client.recipient_id), "%s", val);
            } else if (strcmp(sub, "master_secret") == 0) {
                snprintf(out->pairwise_client.master_secret, sizeof(out->pairwise_client.master_secret), "%s", val);
            } else if (strcmp(sub, "start_sn") == 0) {
                out->pairwise_client.start_sn = strtoull(val, NULL, 10);
            } else { fclose(f); return -1; }
        } else if (strcmp(key, "group.gid") == 0) {
            snprintf(out->group_gid, sizeof(out->group_gid), "%s", val);
        } else if (strcmp(key, "group.master_secret") == 0) {
            snprintf(out->group_master_secret, sizeof(out->group_master_secret), "%s", val);
        } else if (strcmp(key, "group.master_salt") == 0) {
            snprintf(out->group_master_salt, sizeof(out->group_master_salt), "%s", val);
        } else if (strcmp(key, "group.aead_alg") == 0) {
            out->group_aead_alg = atoi(val);
        } else if (strcmp(key, "group.hkdf_alg") == 0) {
            out->group_hkdf_alg = atoi(val);
        } else if (strcmp(key, "group.alg_group_enc") == 0) {
            out->group_alg_group_enc = atoi(val);
        } else if (strcmp(key, "group.alg_signature") == 0) {
            out->group_alg_signature = atoi(val);
        } else if (strcmp(key, "group.alg_pairwise_key_agreement") == 0) {
            out->group_alg_pairwise_key_agreement = atoi(val);
        } else if (strcmp(key, "group.replay_window") == 0) {
            out->group_replay_window = atoi(val);
        } else if (strcmp(key, "group.gm_cred") == 0) {
            snprintf(out->group_gm_cred, sizeof(out->group_gm_cred), "%s", val);
        } else if (strcmp(key, "group.sender_id") == 0) {
            snprintf(out->group_sender_id, sizeof(out->group_sender_id), "%s", val);
        } else if (strcmp(key, "group.sender_cred") == 0) {
            snprintf(out->group_sender_cred, sizeof(out->group_sender_cred), "%s", val);
        } else if (strcmp(key, "group.sender_private_key") == 0) {
            snprintf(out->group_sender_private_key, sizeof(out->group_sender_private_key), "%s", val);
        } else if (strcmp(key, "group.start_sn") == 0) {
            out->group_start_sn = strtoull(val, NULL, 10);
        } else if (strncmp(key, "group.recipient.", 16) == 0 && key[16] >= '1' && key[16] <= '3' && key[17] == '.') {
            int n = key[16] - '1';
            const char *sub = key + 18;
            if (n >= out->num_group_recipients) out->num_group_recipients = n + 1;
            if (strcmp(sub, "id") == 0) {
                snprintf(out->group_recipients[n].id, sizeof(out->group_recipients[n].id), "%s", val);
            } else if (strcmp(sub, "cred") == 0) {
                snprintf(out->group_recipients[n].cred, sizeof(out->group_recipients[n].cred), "%s", val);
            } else { fclose(f); return -1; }
        } else {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

int sec_conf_pairwise_text(const sec_config_t *conf, int n, char *buf, size_t len) {
    const sec_conf_pairwise_ctx_t *pw = conf->is_server ? &conf->pairwise_server[n] : &conf->pairwise_client;

    char tmp[2048];
    int written = snprintf(tmp, sizeof(tmp),
        "master_secret,hex,\"%s\"\n"
        "%s%s%s"
        "replay_window,integer,%d\n"
        "aead_alg,integer,%d\n"
        "hkdf_alg,integer,%d\n"
        "rfc8613_b_1_2,bool,%s\n"
        "sender_id,hex,\"%s\"\n"
        "recipient_id,hex,\"%s\"\n",
        pw->master_secret,
        conf->pairwise_master_salt[0] ? "master_salt,hex,\"" : "",
        conf->pairwise_master_salt[0] ? conf->pairwise_master_salt : "",
        conf->pairwise_master_salt[0] ? "\"\n" : "",
        conf->pairwise_replay_window,
        conf->pairwise_aead_alg,
        conf->pairwise_hkdf_alg,
        conf->pairwise_rfc8613_b_1_2 ? "true" : "false",
        pw->sender_id,
        pw->recipient_id
    );

    if (written < 0 || (size_t)written >= sizeof(tmp)) return -1;
    if ((size_t)written >= len) return -1;
    strcpy(buf, tmp);
    return 0;
}

int sec_conf_group_text(const sec_config_t *conf, char *buf, size_t len) {
    char tmp[4096];
    char recips[2048] = "";

    for (int i = 0; i < conf->num_group_recipients; i++) {
        char r[2048];
        snprintf(r, sizeof(r),
            "complex_recipient,config,'\n"
            "recipient_id,hex,\"%s\"\n"
            "group_mode,bool,true\n"
            "gr_public_cred,pub_ccs,\"%s\"\n"
            "'\n",
            conf->group_recipients[i].id,
            conf->group_recipients[i].cred
        );
        strlcat(recips, r, sizeof(recips));
    }

    int written = snprintf(tmp, sizeof(tmp),
        "master_secret,hex,\"%s\"\n"
        "%s%s%s"
        "id_context,hex,\"%s\"\n"
        "replay_window,integer,%d\n"
        "aead_alg,integer,%d\n"
        "hkdf_alg,integer,%d\n"
        "alg_group_enc,integer,%d\n"
        "alg_signature,integer,%d\n"
        "alg_pairwise_key_agreement,integer,%d\n"
        "rfc8613_b_1_2,bool,false\n"
        "%s%s%s"
        "complex_sender,config,'\n"
        "sender_id,hex,\"%s\"\n"
        "group_mode,bool,true\n"
        "gs_public_cred,pub_ccs,\"%s\"\n"
        "gs_private_key,pri_asn1,\"302e020100300506032b657004220420%s\"\n"
        "'\n"
        "%s",
        conf->group_master_secret,
        conf->group_master_salt[0] ? "master_salt,hex,\"" : "",
        conf->group_master_salt[0] ? conf->group_master_salt : "",
        conf->group_master_salt[0] ? "\"\n" : "",
        conf->group_gid,
        conf->group_replay_window,
        conf->group_aead_alg,
        conf->group_hkdf_alg,
        conf->group_alg_group_enc,
        conf->group_alg_signature,
        conf->group_alg_pairwise_key_agreement,
        conf->group_gm_cred[0] ? "gm_cred,pub_ccs,\"" : "",
        conf->group_gm_cred[0] ? conf->group_gm_cred : "",
        conf->group_gm_cred[0] ? "\"\n" : "",
        conf->group_sender_id,
        conf->group_sender_cred,
        conf->group_sender_private_key,
        recips
    );

    if (written < 0 || (size_t)written >= sizeof(tmp)) return -1;
    if ((size_t)written >= len) return -1;
    strcpy(buf, tmp);
    return 0;
}
