#include "tap.h"
#include "../../src/sec/sec_ir.h"
#include <string.h>
#include <stdlib.h>
#include <cbor.h>

static int has_key(cbor_item_t *map, uint64_t key) {
    struct cbor_pair *pairs = cbor_map_handle(map);
    for (size_t i = 0; i < cbor_map_size(map); i++)
        if (cbor_isa_uint(pairs[i].key) && cbor_get_int(pairs[i].key) == key) return 1;
    return 0;
}

static int decode_map(cbor_item_t *map) {
    uint8_t *wire = NULL;
    size_t len = 0;
    if (!cbor_serialize_alloc(map, &wire, &len)) return -1;
    tp_info_t tp = {0};
    const uint8_t *ph, *ln;
    size_t ph_len, ln_len;
    int rc = sec_ir_decode(wire, len, &tp, &ph, &ph_len, &ln, &ln_len);
    free(wire);
    return rc;
}

int main(void) {
    tp_info_t tp_in = {
        .server_host = "127.0.0.1",
        .server_port = 5683,
        .client_host = "224.0.1.187",
        .client_port = 61616,
        .token = {0},
        .token_len = 0
    };
    uint8_t ph[] = { 0x01, 0x02, 0x03 };
    uint8_t ln[] = { 0x04, 0x05 };

    uint8_t *enc = NULL;
    size_t enc_len = 0;

    int rc = sec_ir_encode(&tp_in, ph, sizeof(ph), ln, sizeof(ln), &enc, &enc_len);
    OK(rc == 0, "Encoded keys 0, 1, 2");
    OK(enc != NULL && enc_len > 0, "Encoded bytes generated");

    tp_info_t tp_out = {0};
    const uint8_t *ph_out, *ln_out;
    size_t ph_out_len, ln_out_len;

    rc = sec_ir_decode(enc, enc_len, &tp_out, &ph_out, &ph_out_len, &ln_out, &ln_out_len);
    OK(rc == 0, "Decoded valid map");
    OK(strcmp(tp_out.server_host, tp_in.server_host) == 0 && tp_out.server_port == tp_in.server_port, "tp_info server address matches");
    OK(strcmp(tp_out.client_host, tp_in.client_host) == 0 && tp_out.client_port == tp_in.client_port, "tp_info client address matches");
    OK(ph_out_len == sizeof(ph) && memcmp(ph_out, ph, ph_out_len) == 0, "ph_req matches");
    OK(ln_out_len == sizeof(ln) && memcmp(ln_out, ln, ln_out_len) == 0, "last_notif matches");

    struct cbor_load_result result;
    cbor_item_t *map = cbor_load(enc, enc_len, &result);
    OK(map && cbor_isa_map(map) && cbor_map_size(map) == 3 &&
       has_key(map, 0) && has_key(map, 1) && has_key(map, 2), "Emitted exactly keys 0, 1, 2");
    OK(!has_key(map, 5) && !has_key(map, 6), "Keys 5/6 not emitted");
    cbor_item_t *extended = cbor_new_indefinite_map();
    struct cbor_pair *original = cbor_map_handle(map);
    int copied = extended != NULL;
    for (size_t i = 0; copied && i < cbor_map_size(map); i++)
        copied = cbor_map_add(extended, original[i]);
    cbor_item_t *key5 = cbor_build_uint8(5);
    cbor_item_t *val5 = cbor_build_bytestring((const uint8_t *)"test", 4);
    OK(copied && cbor_map_add(extended, (struct cbor_pair){.key = key5, .value = val5}),
       "Added optional key 5 fixture");
    cbor_decref(&key5);
    cbor_decref(&val5);
    uint8_t *enc2 = NULL;
    size_t enc2_len = 0;
    OK(cbor_serialize_alloc(extended, &enc2, &enc2_len) > 0 && has_key(extended, 5),
       "Serialized fixture with key 5");

    rc = sec_ir_decode(enc2, enc2_len, &tp_out, &ph_out, &ph_out_len, &ln_out, &ln_out_len);
    OK(rc == 0, "Decoded map with unknown keys successfully");
    OK(ph_out_len == sizeof(ph), "Unknown keys ignored (ph_req present)");
    OK(ln_out_len == sizeof(ln), "Unknown keys ignored (last_notif present)");

    /* A present key 1 or 2 has to be a CBOR byte string (MO-15 §4.2). */
    cbor_item_t *bad = cbor_load(enc, enc_len, &result);
    struct cbor_pair *pairs = cbor_map_handle(bad);
    for (size_t i = 0; i < cbor_map_size(bad); i++) {
        if (cbor_isa_uint(pairs[i].key) && cbor_get_int(pairs[i].key) == 1) {
            cbor_decref(&pairs[i].value);
            pairs[i].value = cbor_build_uint8(1);
            break;
        }
    }
    OK(decode_map(bad) < 0, "Non-byte-string key 1 rejected");
    cbor_decref(&bad);
    bad = cbor_load(enc, enc_len, &result);
    pairs = cbor_map_handle(bad);
    for (size_t i = 0; i < cbor_map_size(bad); i++) {
        if (cbor_isa_uint(pairs[i].key) && cbor_get_int(pairs[i].key) == 2) {
            cbor_decref(&pairs[i].value);
            pairs[i].value = cbor_build_uint8(2);
            break;
        }
    }
    OK(decode_map(bad) < 0, "Non-byte-string key 2 rejected");
    cbor_decref(&bad);

    uint8_t *no_ph = NULL;
    size_t no_ph_len = 0;
    OK(sec_ir_encode(&tp_in, NULL, 0, ln, sizeof(ln), &no_ph, &no_ph_len) == 0,
       "Encoded response without key 1");
    rc = sec_ir_decode(no_ph, no_ph_len, &tp_out, &ph_out, &ph_out_len, &ln_out, &ln_out_len);
    OK(rc == 0 && ph_out == NULL && ph_out_len == 0,
       "Missing key 1 exposed for client withdrawal");
    free(no_ph);

    cbor_decref(&map);
    cbor_decref(&extended);
    free(enc2);
    free(enc);

    DONE();
}
