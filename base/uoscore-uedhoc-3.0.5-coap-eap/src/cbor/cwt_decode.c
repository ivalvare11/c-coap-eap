/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cbor/cwt_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_COSE_Key(zcbor_state_t *state, struct COSE_Key *result);
static bool decode_Claim_Key(zcbor_state_t *state, struct Claim_Key *result);
static bool decode_CWT(zcbor_state_t *state, struct CWT *result);

static bool decode_COSE_Key(zcbor_state_t *state, struct COSE_Key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result =
		(((zcbor_map_start_decode(state) &&
		   (((((zcbor_uint32_expect(state, (1)))) &&
		      (zcbor_int32_decode(state,
					  (&(*result).COSE_Key_uint1int)))) &&
		     (((zcbor_uint32_expect(state, (2)))) &&
		      (zcbor_bstr_decode(state,
					 (&(*result).COSE_Key_uint2bstr)))) &&
		     (((zcbor_int32_expect(state, (-1)))) &&
		      (zcbor_bstr_decode(state,
					 (&(*result).COSE_Key_nintbstr))))) ||
		    (zcbor_list_map_end_force_decode(state), false)) &&
		   zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__,
			  zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_Claim_Key(zcbor_state_t *state, struct Claim_Key *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result =
		(((zcbor_map_start_decode(state) &&
		   (((((zcbor_uint32_expect(state, (1)))) &&
		      (decode_COSE_Key(state,
				       (&(*result).Claim_Key_COSE_Key_m))))) ||
		    (zcbor_list_map_end_force_decode(state), false)) &&
		   zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__,
			  zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_CWT(zcbor_state_t *state, struct CWT *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((
		(zcbor_map_start_decode(state) &&
		 (((((zcbor_uint32_expect(state, (2)))) &&
		    (zcbor_tstr_decode(state, (&(*result).CWT_uint2tstr)))) &&
		   (((zcbor_uint32_expect(state, (8)))) &&
		    (decode_Claim_Key(state, (&(*result).CWT_Claim_Key_m))))) ||
		  (zcbor_list_map_end_force_decode(state), false)) &&
		 zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__,
			  zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

int cbor_decode_CWT(const uint8_t *payload, size_t payload_len,
		    struct CWT *result, size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result,
				    payload_len_out, states,
				    (zcbor_decoder_t *)decode_CWT,
				    sizeof(states) / sizeof(zcbor_state_t), 1);
}
