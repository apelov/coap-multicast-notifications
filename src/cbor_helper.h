#ifndef CBOR_HELPER_H
#define CBOR_HELPER_H

#include <stddef.h>
#include <stdint.h>

#define MAX_HOST_LEN 64
#define MAX_TOKEN_LEN 8

typedef struct {
    char server_host[MAX_HOST_LEN];
    uint16_t server_port;
    char client_host[MAX_HOST_LEN];
    uint16_t client_port;
    uint8_t token[MAX_TOKEN_LEN];
    size_t token_len;
} tp_info_t;

/**
 * Encodes the tp_info_t structure into standard CBOR format matching the Java reference implementation.
 * 
 * @param tp The input transport info.
 * @param out_buf Output pointer where the allocated buffer is stored. The caller must free this buffer.
 * @param out_len Output pointer for the buffer length.
 * @return 0 on success, -1 on failure.
 */
int encode_observation_info(const tp_info_t *tp, uint8_t **out_buf, size_t *out_len);

/**
 * Encodes the tp_info_t structure plus the optional ph_req and last_notif fields
 * into standard CBOR format matching the Java reference implementation.
 */
int encode_observation_info_full(const tp_info_t *tp,
                                 const uint8_t *ph_req, size_t ph_req_len,
                                 const uint8_t *last_notif, size_t last_notif_len,
                                 uint8_t **out_buf, size_t *out_len);


/**
 * Decodes a CBOR buffer into the tp_info_t structure.
 * 
 * @param buf The input CBOR buffer.
 * @param buf_len The length of the input buffer.
 * @param out_tp The output transport info structure.
 * @return 0 on success, -1 on failure.
 */
int decode_observation_info(const uint8_t *buf, size_t buf_len, tp_info_t *out_tp);

#endif /* CBOR_HELPER_H */
