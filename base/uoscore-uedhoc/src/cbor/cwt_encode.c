/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "cbor/cwt_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_COSE_Key(zcbor_state_t *state, const struct COSE_Key *input);
static bool encode_Claim_Key(zcbor_state_t *state, const struct Claim_Key *input);
static bool encode_CWT(zcbor_state_t *state, const struct CWT *input);


static bool encode_COSE_Key(
		zcbor_state_t *state, const struct COSE_Key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((((zcbor_uint32_put(state, (1))))
	&& (zcbor_int32_encode(state, (&(*input).COSE_Key_uint1int))))
	&& (((zcbor_uint32_put(state, (2))))
	&& (zcbor_bstr_encode(state, (&(*input).COSE_Key_uint2bstr))))
	&& (((zcbor_int32_put(state, (-1))))
	&& (zcbor_bstr_encode(state, (&(*input).COSE_Key_nintbstr))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_Claim_Key(
		zcbor_state_t *state, const struct Claim_Key *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 1) && (((((zcbor_uint32_put(state, (1))))
	&& (encode_COSE_Key(state, (&(*input).Claim_Key_COSE_Key_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_CWT(
		zcbor_state_t *state, const struct CWT *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 2) && (((((zcbor_uint32_put(state, (2))))
	&& (zcbor_tstr_encode(state, (&(*input).CWT_uint2tstr))))
	&& (((zcbor_uint32_put(state, (8))))
	&& (encode_Claim_Key(state, (&(*input).CWT_Claim_Key_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_CWT(
		uint8_t *payload, size_t payload_len,
		const struct CWT *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_CWT, sizeof(states) / sizeof(zcbor_state_t), 1);
}
