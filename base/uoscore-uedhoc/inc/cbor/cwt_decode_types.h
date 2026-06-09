/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef CWT_DECODE_TYPES_H__
#define CWT_DECODE_TYPES_H__

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

struct COSE_Key {
	int32_t COSE_Key_uint1int;
	struct zcbor_string COSE_Key_uint2bstr;
	struct zcbor_string COSE_Key_nintbstr;
};

struct Claim_Key {
	struct COSE_Key Claim_Key_COSE_Key_m;
};

struct CWT {
	struct zcbor_string CWT_uint2tstr;
	struct Claim_Key CWT_Claim_Key_m;
};

#ifdef __cplusplus
}
#endif

#endif /* CWT_DECODE_TYPES_H__ */
