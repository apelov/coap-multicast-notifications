#include "sec_ir.h"
#include <cbor.h>
#include <string.h>

int sec_ir_encode(const tp_info_t *tp, const uint8_t *ph, size_t ph_len, const uint8_t *ln, size_t ln_len, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return -1;

    int rc = encode_observation_info_full(tp, ph, ph_len, ln, ln_len, out, out_len);
    return rc;
}

int sec_ir_decode(const uint8_t *data, size_t len, tp_info_t *tp, const uint8_t **ph, size_t *ph_len, const uint8_t **ln, size_t *ln_len) {
    *ph = NULL; *ph_len = 0;
    *ln = NULL; *ln_len = 0;

    struct cbor_load_result result;
    cbor_item_t *map = cbor_load(data, len, &result);
    if (!map || !cbor_isa_map(map)) {
        if (map) cbor_decref(&map);
        return -1;
    }

    int rc = decode_observation_info(data, len, tp);

    size_t size = cbor_map_size(map);
    struct cbor_pair *pairs = cbor_map_handle(map);
    for (size_t i = 0; i < size; i++) {
        if (!cbor_isa_uint(pairs[i].key)) continue;
        uint64_t key = cbor_get_int(pairs[i].key);
        if (key == 1) {
            if (!cbor_isa_bytestring(pairs[i].value)) { rc = -1; break; }
            *ph = cbor_bytestring_handle(pairs[i].value);
            *ph_len = cbor_bytestring_length(pairs[i].value);
        } else if (key == 2) {
            if (!cbor_isa_bytestring(pairs[i].value)) { rc = -1; break; }
            *ln = cbor_bytestring_handle(pairs[i].value);
            *ln_len = cbor_bytestring_length(pairs[i].value);
        }
        // keys >= 3 are ignored per conformance
    }

    if (rc < 0) {
        cbor_decref(&map);
        return -1;
    }

    /* libcbor owns the decoded byte strings; copy them before releasing the map. */
    static uint8_t s_ph[256];
    static uint8_t s_ln[256];

    if (*ph) {
        if (*ph_len > sizeof(s_ph)) { cbor_decref(&map); return -1; }
        memcpy(s_ph, *ph, *ph_len);
        *ph = s_ph;
    }
    if (*ln) {
        if (*ln_len > sizeof(s_ln)) { cbor_decref(&map); return -1; }
        memcpy(s_ln, *ln, *ln_len);
        *ln = s_ln;
    }

    cbor_decref(&map);
    return 0;
}
