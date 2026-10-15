#ifndef SEC_IR_H
#define SEC_IR_H

#include <stdint.h>
#include <stddef.h>
#include "../../src/cbor_helper.h"

int sec_ir_encode(const tp_info_t *tp, const uint8_t *ph, size_t ph_len, const uint8_t *ln, size_t ln_len, uint8_t **out, size_t *out_len);
int sec_ir_decode(const uint8_t *data, size_t len, tp_info_t *tp, const uint8_t **ph, size_t *ph_len, const uint8_t **ln, size_t *ln_len);

#endif
