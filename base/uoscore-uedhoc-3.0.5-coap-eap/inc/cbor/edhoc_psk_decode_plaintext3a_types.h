/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_PSK_DECODE_PLAINTEXT3A_TYPES_H__
#define EDHOC_PSK_DECODE_PLAINTEXT3A_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct ptxt3a_psk {
	union {
		struct zcbor_string ptxt3a_psk_ID_CRED_PSK_bstr;
		int32_t ptxt3a_psk_ID_CRED_PSK_int;
	};
	enum {
		ptxt3a_psk_ID_CRED_PSK_bstr_c,
		ptxt3a_psk_ID_CRED_PSK_int_c,
	} ptxt3a_psk_ID_CRED_PSK_choice;
	struct zcbor_string ptxt3a_psk_CIPHERTEXT_3B;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_PSK_DECODE_PLAINTEXT3A_TYPES_H__ */
