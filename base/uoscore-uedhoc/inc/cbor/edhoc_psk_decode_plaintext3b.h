/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_PSK_DECODE_PLAINTEXT3B_H__
#define EDHOC_PSK_DECODE_PLAINTEXT3B_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/edhoc_psk_decode_plaintext3b_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_decode_ptxt3b_psk_EAD_3(
		const uint8_t *payload, size_t payload_len,
		struct ptxt3b_psk_EAD_3 *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* EDHOC_PSK_DECODE_PLAINTEXT3B_H__ */
