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
#include "cbor/edhoc_psk_decode_plaintext3a.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_ptxt3a_psk(zcbor_state_t *state, struct ptxt3a_psk *result);


static bool decode_ptxt3a_psk(
		zcbor_state_t *state, struct ptxt3a_psk *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).ptxt3a_psk_ID_CRED_PSK_bstr)))) && (((*result).ptxt3a_psk_ID_CRED_PSK_choice = ptxt3a_psk_ID_CRED_PSK_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).ptxt3a_psk_ID_CRED_PSK_int)))) && (((*result).ptxt3a_psk_ID_CRED_PSK_choice = ptxt3a_psk_ID_CRED_PSK_int_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).ptxt3a_psk_CIPHERTEXT_3B)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_ptxt3a_psk(
		const uint8_t *payload, size_t payload_len,
		struct ptxt3a_psk *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ptxt3a_psk, sizeof(states) / sizeof(zcbor_state_t), 2);
}
