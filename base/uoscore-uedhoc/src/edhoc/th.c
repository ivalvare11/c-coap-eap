/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"

#include "edhoc/th.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_encode_data_2.h"
#include "cbor/edhoc_encode_th2.h"

/**
 * @brief   			Setups a data structure used as input for th2, 
 * 				namely CBOR sequence H( G_Y, C_R, H(message_1)).
 *
 * @param[in] hash_msg1 	Hash of message 1.
 * @param[in] g_y 		Ephemeral public DH key.
 * @param[out] th2_input	The result.
 * @retval			Ok or error.
 */
static inline enum err th2_input_encode(struct byte_array *hash_msg1,
					struct byte_array *g_y,
					struct byte_array *th2_input)
{
	size_t payload_len_out;
	struct th2 th2;

	/*Encode hash_msg1*/
	th2.th2_hash_msg1.value = hash_msg1->ptr;
	th2.th2_hash_msg1.len = hash_msg1->len;

	/*Encode G_Y*/
	th2.th2_G_Y.value = g_y->ptr;
	th2.th2_G_Y.len = g_y->len;

	TRY_EXPECT(cbor_encode_th2(th2_input->ptr, th2_input->len, &th2,
				   &payload_len_out),
		   0);

	/* Get the the total th2 length */
	th2_input->len = (uint32_t)payload_len_out;

	PRINT_ARRAY("Input to calculate TH_2 (CBOR Sequence)", th2_input->ptr,
		    th2_input->len);
	return ok;
}

/**
 * @brief   			Setups a data structure used as input for 
 * 				th3 or th4.
 * 
 * @param[in] th23 		th2 or th3.
 * @param[in] plaintext_23 	Plaintext 2 or plaintext 3.
 * @param[in] cred		The credential.
 * @param[out] th34_input 	The result.
 * @retval			Ok or error code.
 */
static enum err th34_input_encode(struct byte_array *th23,
				  struct byte_array *plaintext_23,
				  const struct byte_array *cred,
				  struct byte_array *th34_input)
{
	PRINT_ARRAY("th23", th23->ptr, th23->len);
	PRINT_ARRAY("plaintext_23", plaintext_23->ptr, plaintext_23->len);
	PRINT_ARRAY("cred", cred->ptr, cred->len);

	uint32_t init_len = th34_input->len;

	TRY(encode_bstr(th23, th34_input));
	uint32_t tmp_len = th34_input->len;

	TRY(_memcpy_s(th34_input->ptr + tmp_len,
		      init_len - tmp_len - cred->len, plaintext_23->ptr,
		      plaintext_23->len));

	tmp_len += plaintext_23->len;

	TRY(_memcpy_s(th34_input->ptr + tmp_len, init_len - tmp_len,
		      cred->ptr, cred->len));

	th34_input->len = tmp_len + cred->len;

	PRINT_ARRAY("Input to calculate TH_3/TH_4 (CBOR Sequence)",
		    th34_input->ptr, th34_input->len);
	return ok;
}

/**
 * @brief 			Computes TH_3 or TH4. Where: 
 * 				TH_3 = H(TH_2, PLAINTEXT_2, CRED_R)
 * 				TH_4 = H(TH_3, PLAINTEXT_3, CRED_I)
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] th23 		th2 if we compute TH_3, th3 if we compute TH_4.
 * @param[in] plaintext_23 	The plaintext.
 * @param[in] cred		The credential.
 * @param[out] th34 		The result.
 * @return 			Ok or error. 
 */
enum err th34_calculate(enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred, struct byte_array *th34)
{
	uint32_t th34_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + plaintext_23->len + cred->len;
	BYTE_ARRAY_NEW(th34_input, TH34_INPUT_SIZE, th34_input_len);

	TRY(th34_input_encode(th23, plaintext_23, cred, &th34_input));
	TRY(hash(alg, &th34_input, th34));
	PRINT_ARRAY("TH34", th34->ptr, th34->len);
	return ok;
}

static enum err th3_psk_input_encode(struct byte_array *th2,
				  struct byte_array *plaintext_2,
				  struct byte_array *th3_input)
{
	PRINT_ARRAY("th2", th2->ptr, th2->len);
	PRINT_ARRAY("plaintext_2", plaintext_2->ptr, plaintext_2->len);

	uint32_t init_len = th3_input->len;

	TRY(encode_bstr(th2, th3_input));
	uint32_t tmp_len = th3_input->len;

	TRY(_memcpy_s(th3_input->ptr + tmp_len,
		      init_len - tmp_len, plaintext_2->ptr,
		      plaintext_2->len));

	tmp_len += plaintext_2->len;
	th3_input->len = tmp_len;
	
	PRINT_ARRAY("Input to calculate TH_3_PSK (CBOR Sequence)",
		    th3_input->ptr, th3_input->len);
	return ok;
}

enum err th3_psk_calculate(enum hash_alg alg, struct byte_array *th2,
			struct byte_array *plaintext_2, struct byte_array *th3)
{
	uint32_t th3_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + plaintext_2->len;
	BYTE_ARRAY_NEW(th3_input, TH3_PSK_INPUT_SIZE, th3_input_len);

	TRY(th3_psk_input_encode(th2, plaintext_2, &th3_input));
	TRY(hash(alg, &th3_input, th3));
	PRINT_ARRAY("TH3_PSK", th3->ptr, th3->len);
	return ok;
}

enum err th2_calculate(enum hash_alg alg, struct byte_array *msg1_hash,
		       struct byte_array *g_y, struct byte_array *th2)
{
	BYTE_ARRAY_NEW(th2_input, TH2_INPUT_SIZE,
		       AS_BSTR_SIZE(g_y->len) +
			       AS_BSTR_SIZE(get_hash_len(alg)));
	PRINT_ARRAY("hash_msg1_raw", msg1_hash->ptr, msg1_hash->len);
	TRY(th2_input_encode(msg1_hash, g_y, &th2_input));
	TRY(hash(alg, &th2_input, th2));
	PRINT_ARRAY("TH2", th2->ptr, th2->len);
	return ok;
}

static enum err th4_psk_input_encode(struct byte_array *th3,
				  const struct byte_array *id_cred,
				  const struct byte_array *plaintext_3b,
				  const struct byte_array *cred_i, const struct byte_array *cred_r,
				  struct byte_array *th4_input)
{
	PRINT_ARRAY("th3", th3->ptr, th3->len);
	PRINT_ARRAY("id_cred", id_cred->ptr, id_cred->len);
	PRINT_ARRAY("plaintext_3b", plaintext_3b->ptr, plaintext_3b->len);
	PRINT_ARRAY("cred_i", cred_i->ptr, cred_i->len);
	PRINT_ARRAY("cred_r", cred_r->ptr, cred_r->len);

	uint32_t init_len = th4_input->len;
	printf("TH4 INPUT LEN = %d\n", th4_input->len);

	TRY(encode_bstr(th3, th4_input));
	uint32_t tmp_len = th4_input->len;

	TRY(_memcpy_s(th4_input->ptr + tmp_len,
		      init_len - tmp_len - cred_i->len - cred_r->len - plaintext_3b->len, id_cred->ptr,
		      id_cred->len));

	tmp_len += id_cred->len;

	TRY(_memcpy_s(th4_input->ptr + tmp_len, init_len - tmp_len - cred_i->len - cred_r->len,
		      plaintext_3b->ptr, plaintext_3b->len));

	tmp_len += plaintext_3b->len;

	TRY(_memcpy_s(th4_input->ptr + tmp_len, init_len - tmp_len - cred_r->len,
		      cred_i->ptr, cred_i->len));

	tmp_len += cred_i->len;

	TRY(_memcpy_s(th4_input->ptr + tmp_len, init_len - tmp_len,
		      cred_r->ptr, cred_r->len));

	th4_input->len = tmp_len + cred_r->len;

	PRINT_ARRAY("Input to calculate TH_3/TH_4 (CBOR Sequence)",
		    th4_input->ptr, th4_input->len);
	return ok;
}

enum err th4_psk_calculate(enum hash_alg alg, struct byte_array *th3,
			const struct byte_array *id_cred, const struct byte_array *plaintext_3b,
         const struct byte_array *cred_i, const struct byte_array *cred_r, struct byte_array *th4)
{
	uint32_t th4_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + id_cred->len + cred_i->len + cred_r->len;
	BYTE_ARRAY_NEW(th4_input, TH4_PSK_INPUT_SIZE, th4_input_len);

	TRY(th4_psk_input_encode(th3, id_cred, plaintext_3b, cred_i, cred_r, &th4_input));
	TRY(hash(alg, &th4_input, th4));
	PRINT_ARRAY("TH4", th4->ptr, th4->len);
	return ok;
}
