/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_PSK_DECODE_PLAINTEXT2_TYPES_H__
#define EDHOC_PSK_DECODE_PLAINTEXT2_TYPES_H__

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

struct ptxt2_psk {
	union {
		int32_t ptxt2_psk_C_R_int;
		struct zcbor_string ptxt2_psk_C_R_bstr;
	};
	enum {
		ptxt2_psk_C_R_int_c,
		ptxt2_psk_C_R_bstr_c,
	} ptxt2_psk_C_R_choice;
	struct zcbor_string ptxt2_psk_EAD_2;
	bool ptxt2_psk_EAD_2_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_PSK_DECODE_PLAINTEXT2_TYPES_H__ */
