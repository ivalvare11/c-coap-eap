/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef CWT_ENCODE_H__
#define CWT_ENCODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/cwt_encode_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_encode_CWT(
		uint8_t *payload, size_t payload_len,
		struct CWT *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* CWT_ENCODE_H__ */
