/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include <string.h>

#include "edhoc.h"

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
struct edhoc_mock_cb edhoc_crypto_mock_cb;
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

#ifdef MBEDTLS
/*
IMPORTANT!!!!
make sure MBEDTLS_PSA_CRYPTO_CONFIG is defined in include/mbedtls/mbedtls_config.h


modify setting in include/psa/crypto_config.h
*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <psa/crypto.h>

#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

#endif

#ifdef COMPACT25519
#include <c25519.h>
#include <edsign.h>
#include <compact_x25519.h>
#endif

#ifdef TINYCRYPT
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/ecc_dh.h>
#endif

#ifdef CC310
#include "cc310_platform.h" // cc310_hw_acquire(), cc310_hw_release()
#include "crys_aesccm.h"    // API CCM
#include "crys_aesccm_error.h"
#include "ssi_aes_defs.h" // SaSiAesEncryptMode_t, SASI_AES_ENCRYPT/DECRYPT
#include "crys_hash.h"	  // CRYS_HASH_* API
#include "crys_hash_error.h"
#include "crys_hmac.h"
#include "crys_hmac_error.h"
#include "crys_ecpki_build.h"  // CRYS_ECPKI_BuildPrivKey/BuildPublKey
#include "crys_ecpki_domain.h" // CRYS_ECPKI_DomainID_secp256r1
#include "crys_ecpki_error.h"
#include "crys_ecpki_types.h" // CRYS_ECPKI_UserPrivKey_t

#include "crys_ecpki_dh.h"
#include "crys_ecpki_kg.h" // CRYS_ECPKI_KG_TempData_t

#include "crys_ecpki_ecdsa.h" // CRYS_ECDSA_Sign/Verify
// #include "crys_ecdsa_error.h"
#include "crys_rnd.h" // RND for ECDSA Sign
#include "crys_rnd_error.h"

int aead_failed = 0;
/* ===== Debug helpers ===== */
#ifndef AEAD_DEBUG_MAX_DUMP
#define AEAD_DEBUG_MAX_DUMP 64u /* max bytes to dump into buffer */
#endif

static void dump_hex_limited(const char *label, const uint8_t *p, size_t n)
{
	size_t m = n > AEAD_DEBUG_MAX_DUMP ? AEAD_DEBUG_MAX_DUMP : n;
	PRINTF("%s (len=%u)%s:\n", label, (unsigned)n, n > AEAD_DEBUG_MAX_DUMP ? " [trunc]" : "");
	for (size_t i = 0; i < m; i++)
	{
		PRINTF("%02X%s", p[i], ((i + 1) % 16 == 0) ? "\n" : " ");
	}
	if (m && (m % 16))
		PRINTF("\n");
}

static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < n; i++)
		diff |= (uint8_t)(a[i] ^ b[i]);
	return diff == 0;
}

/* 0 if equal */
static int ct_memeq_ret0(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < n; i++)
		diff |= (uint8_t)(a[i] ^ b[i]);
	return (int)diff;
}

/* Comparison for TAG */
static int ct_memcmp_consttime(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= (uint8_t)(a[i] ^ b[i]);
	return acc; /* 0 if equal */
}

/* ENCRYPT: in=PT, out=CT, tag(out) */
/* DECRYPT: in=CT (without tag), out=PT, tag(in) */
static int cc310_ccm_auth_crypt(enum aes_operation op,
				const struct byte_array *key,
				const struct byte_array *nonce,
				const struct byte_array *aad,
				const struct byte_array *in,
				struct byte_array *out,
				struct byte_array *tag)
{
	if (!key || !nonce || !in || !out || !tag)
		return -1;

	if (!(key->len == 16 || key->len == 24 || key->len == 32))
		return -1;

	if (nonce->len < 7 || nonce->len > 13)
		return -1;

	if (tag->len < 4 || tag->len > 16 || (tag->len & 1))
		return -1;

	CRYS_AESCCM_KeySize_t key_id =
	    (key->len == 16) ? CRYS_AES_Key128BitSize : (key->len == 24) ? CRYS_AES_Key192BitSize
									 : CRYS_AES_Key256BitSize;

	SaSiAesEncryptMode_t mode =
	    (op == ENCRYPT) ? SASI_AES_ENCRYPT : SASI_AES_DECRYPT;

	CRYS_AESCCM_Key_t key_buf = {0};
	memcpy(key_buf, key->ptr, key->len);

	CRYS_AESCCM_UserContext_t ctx;
	CRYSError_t rc;

	PRINTF("== cc310_ccm_auth_crypt: op=%s key=%u nonce=%u aad=%u in=%u out=%u tag=%u ==\n",
	       (op == ENCRYPT) ? "ENC" : "DEC",
	       (unsigned)key->len, (unsigned)nonce->len,
	       (unsigned)(aad ? aad->len : 0),
	       (unsigned)in->len, (unsigned)out->len, (unsigned)tag->len);

	rc = CRYS_AESCCM_Init(&ctx, mode,
			      key_buf, key_id,
			      aad ? aad->len : 0,
			      in->len, // total plaintext/ciphertext length
			      nonce->ptr, nonce->len,
			      tag->len);

	PRINTF("[CCM] Init rc=0x%08X\n", rc);
	if (rc != CRYS_OK)
		return -1;

	if (aad && aad->len)
	{
		rc = CRYS_AESCCM_BlockAdata(&ctx, aad->ptr, aad->len);
		PRINTF("[CCM] AAD rc=0x%08X\n", rc);
		if (rc != CRYS_OK)
			return -1;
	}

	uint32_t full = in->len & ~0xF; // *16
	uint32_t rem = in->len - full;

	PRINTF("[CCM] full=%u rem=%u\n", full, rem);

	if (full)
	{
		rc = CRYS_AESCCM_BlockTextData(&ctx,
					       in->ptr,
					       full,
					       out->ptr);
		PRINTF("[CCM] BlockText rc=0x%08X\n", rc);
		if (rc != CRYS_OK)
			return -1;
	}

	uint8_t *last_in = (rem ? in->ptr + full : NULL);
	uint8_t *last_out = (rem ? out->ptr + full : NULL);

	if (rem)
	{
		PRINTF("[DEBUG] last_in  (%u bytes): ", rem);
		for (uint32_t i = 0; i < rem; i++)
			PRINTF("%02X ", last_in[i]);
		PRINTF("\n");
	}

	uint8_t mac_len8 = tag->len;

	rc = CRYS_AESCCM_Finish(&ctx,
				last_in, rem,
				last_out,
				tag->ptr, // for ENCRYPT, out of the tag
					  // for DECRYPT, tag received
				&mac_len8);

	PRINTF("[CCM] Finish rc=0x%08X mac_len8=%u\n", rc, mac_len8);

	if (op == ENCRYPT)
	{
		PRINTF("[CCM] tag generated:\n");
		for (uint32_t i = 0; i < mac_len8; i++)
			PRINTF("%02X ", tag->ptr[i]);
		PRINTF("\n");
	}

	if (rc != CRYS_OK)
		return -1;

	return 0;
}

// DER (SEQUENCE { INTEGER r; INTEGER s; }) → r||s (64B)
static int der_to_rs64(const uint8_t *der, size_t der_len, uint8_t out_rs[64])
{
	if (der_len < 8 || der[0] != 0x30)
		return -1;
	size_t idx = 1, seqlen = 0;
	if (idx >= der_len)
		return -1;
	if ((der[idx] & 0x80) == 0)
	{
		seqlen = der[idx++];
	}
	else
	{
		size_t n = der[idx++] & 0x7F;
		if (!n || idx + n > der_len)
			return -1;
		while (n--)
			seqlen = (seqlen << 8) | der[idx++];
		if (idx + seqlen > der_len)
			return -1;
	}
	if (idx >= der_len || der[idx++] != 0x02)
		return -1;
	if (idx >= der_len)
		return -1;
	size_t lr;
	if ((der[idx] & 0x80) == 0)
	{
		lr = der[idx++];
	}
	else
	{
		size_t n = der[idx++] & 0x7F;
		if (!n || idx + n > der_len)
			return -1;
		lr = 0;
		while (n--)
			lr = (lr << 8) | der[idx++];
	}
	if (idx + lr > der_len)
		return -1;
	const uint8_t *r = der + idx;
	idx += lr;

	if (idx >= der_len || der[idx++] != 0x02)
		return -1;
	if (idx >= der_len)
		return -1;
	size_t ls;
	if ((der[idx] & 0x80) == 0)
	{
		ls = der[idx++];
	}
	else
	{
		size_t n = der[idx++] & 0x7F;
		if (!n || idx + n > der_len)
			return -1;
		ls = 0;
		while (n--)
			ls = (ls << 8) | der[idx++];
	}
	if (idx + ls > der_len)
		return -1;
	const uint8_t *s = der + idx;

	if (lr > 33 || ls > 33)
		return -1;
	size_t r_off = (lr == 33 && r[0] == 0x00) ? 1 : 0;
	size_t s_off = (ls == 33 && s[0] == 0x00) ? 1 : 0;
	size_t r_len = lr - r_off;
	size_t s_len = ls - s_off;
	if (r_len > 32 || s_len > 32)
		return -1;

	memset(out_rs, 0, 64);
	memcpy(out_rs + (32 - r_len), r + r_off, r_len);
	memcpy(out_rs + 32 + (32 - s_len), s + s_off, s_len);
	return 0;
}

/* r||s (64B) -> DER (SEQUENCE { INTEGER r; INTEGER s; }) */
static int rs64_to_der(const uint8_t rs[64], uint8_t der_out[80], size_t *der_len)
{
	const uint8_t *r = rs, *s = rs + 32;
	size_t r_off = 0;
	while (r_off < 32 && r[r_off] == 0)
		r_off++;
	size_t s_off = 0;
	while (s_off < 32 && s[s_off] == 0)
		s_off++;
	size_t r_len = 32 - r_off, s_len = 32 - s_off;

	uint8_t r_pad = (r_len > 0 && (r[r_off] & 0x80)) ? 1 : 0;
	uint8_t s_pad = (s_len > 0 && (s[s_off] & 0x80)) ? 1 : 0;

	size_t r_enc_len = r_pad + r_len, s_enc_len = s_pad + s_len;
	size_t seq_content = 2 + r_enc_len + 2 + s_enc_len;
	size_t idx = 0;

	der_out[idx++] = 0x30;
	if (seq_content < 128)
		der_out[idx++] = (uint8_t)seq_content;
	else
	{
		der_out[idx++] = 0x81;
		der_out[idx++] = (uint8_t)seq_content;
	}

	der_out[idx++] = 0x02;
	der_out[idx++] = (uint8_t)r_enc_len;
	if (r_pad)
		der_out[idx++] = 0x00;
	memcpy(&der_out[idx], r + r_off, r_len);
	idx += r_len;

	der_out[idx++] = 0x02;
	der_out[idx++] = (uint8_t)s_enc_len;
	if (s_pad)
		der_out[idx++] = 0x00;
	memcpy(&der_out[idx], s + s_off, s_len);
	idx += s_len;

	*der_len = idx;
	return 0;
}

#endif

#ifdef MBEDTLS
#define TRY_EXPECT_PSA(x, expected_result, key_id, err_code)            \
	do                                                              \
	{                                                               \
		int retval = (int)(x);                                  \
		if ((expected_result) != retval)                        \
		{                                                       \
			if (PSA_KEY_HANDLE_INIT != (key_id))            \
			{                                               \
				psa_destroy_key(key_id);                \
			}                                               \
			handle_external_runtime_error(retval, __FILE__, \
						      __LINE__);        \
			return err_code;                                \
		}                                                       \
	} while (0)

/**
 * @brief Decompresses an elliptic curve point.
 *
 *
 * @param grp elliptic curve group point
 * @param input the compressed key
 * @param ilen the lenhgt if the compressed key
 * @param output the uncopressed key
 * @param olen the lenhgt of the output
 * @param osize the actual available size of the out buffer
 * @return 0 on success
 */
static inline int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
					 const unsigned char *input,
					 size_t ilen, unsigned char *output,
					 size_t *olen, size_t osize)
{
	int ret;
	size_t plen;
	mbedtls_mpi r;
	mbedtls_mpi x;
	mbedtls_mpi n;

	plen = mbedtls_mpi_size(&grp->P);

	*olen = 2 * plen + 1;

	if (osize < *olen)
		return (MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

	// output will consist of 0x04|X|Y
	memcpy(output + 1, input, ilen);
	output[0] = 0x04;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&n);

	// x <= input
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input, plen));

	// r = x^2
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

	// r = x^2 + a
	if (grp->A.p == NULL)
	{
		// Special case where a is -3
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
	}
	else
	{
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
	}

	// r = x^3 + ax
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

	// r = x^3 + ax + b
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

	// Calculate square root of r over finite field P:
	//   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

	// n = P + 1
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

	// n = (P + 1) / 4
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

	// r ^ ((P + 1) / 4) (mod p)
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

	// Select solution that has the correct "sign" (equals odd/even solution in finite group)
	if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0))
	{
		// r = p - r
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
	}

	// y => output
	ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&n);

	return (ret);
}

#endif

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
	if (alg == SHA_256)
	{
#ifdef TINYCRYPT
		struct tc_sha256_state_struct s;
		TRY_EXPECT(tc_sha256_init(&s), 1);
		TRY_EXPECT(tc_sha256_update(&s, in->ptr, in->len), 1);
		TRY_EXPECT(tc_sha256_final(out->ptr, &s), 1);
		out->len = HASH_SIZE;
		return ok;
#endif

#ifdef CC310

		if (alg == SHA_256)
		{
			CRYSError_t rc;
			CRYS_HASHUserContext_t ctx;
			CRYS_HASH_Result_t digest_words; // uint32_t[CRYS_HASH_RESULT_SIZE_IN_WORDS]

			cc310_hw_acquire();

			rc = CRYS_HASH_Init(&ctx, CRYS_HASH_SHA256_mode);
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][hash] Init failed: 0x%08X\n", rc);
				rc = sha_failed;
				goto exit;
			}

			rc = CRYS_HASH_Update(&ctx, in->ptr, (size_t)in->len);
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][hash] Update failed: 0x%08X\n", rc);
				rc = sha_failed;
				goto exit;
			}

			rc = CRYS_HASH_Finish(&ctx, digest_words);
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][hash] Finish failed: 0x%08X\n", rc);
				rc = sha_failed;
				goto exit;
			}

			// Size validation
			if (out->len < CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES)
			{
				PRINTF("[CC310][hash] Output buffer too small\n");
				rc = buffer_to_small;
				goto exit;
			}

			// Copy digest (32 bytes) to the out buffer
			memcpy(out->ptr,
			       (const uint8_t *)digest_words,
			       CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES);

			out->len = HASH_SIZE; // 32
			return ok;

		exit:
			// Secure clean
			cc310_hw_release();
			memset(&ctx, 0, sizeof(ctx));
			memset(digest_words, 0, sizeof(digest_words));

			if (rc == ok)
				PRINTF("[CC310][hash] Completed successfully\n");
			return (enum err)rc;
		}

#elif MBEDTLS

		PRINTF("crypto_wrapper.c entra mbedtls hash\n");
		size_t length;
		TRY_EXPECT(psa_hash_compute(PSA_ALG_SHA_256, in->ptr, in->len,
					    out->ptr, HASH_SIZE, &length),
			   PSA_SUCCESS);
		if (length != HASH_SIZE)
		{
			return sha_failed;
		}
		out->len = HASH_SIZE;
		PRINT_ARRAY("hash", out->ptr, out->len);
		return ok;
#endif
	}

	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	/*"Note that [RFC5869] specifies that if the salt is not provided,
	it is set to a string of zeros.  For implementation purposes,
	not providing the salt is the same as setting the salt to the empty byte
	string. OSCORE sets the salt default value to empty byte string, which
	is converted to a string of zeroes (see Section 2.2 of [RFC5869])".*/

	/*all currently prosed suites use hmac-sha256*/
	if (alg != SHA_256)
	{
		return crypto_operation_not_implemented;
	}
#ifdef TINYCRYPT
	struct tc_hmac_state_struct h;
	memset(&h, 0x00, sizeof(h));
	if (salt->ptr == NULL || salt->len == 0)
	{
		uint8_t zero_salt[32] = {0};
		TRY_EXPECT(tc_hmac_set_key(&h, zero_salt, 32), 1);
	}
	else
	{
		TRY_EXPECT(tc_hmac_set_key(&h, salt->ptr, salt->len), 1);
	}
	TRY_EXPECT(tc_hmac_init(&h), 1);
	TRY_EXPECT(tc_hmac_update(&h, ikm->ptr, ikm->len), 1);
	TRY_EXPECT(tc_hmac_final(out, TC_SHA256_DIGEST_SIZE, &h), 1);
#endif

#ifdef CC310
	if (alg == SHA_256)
	{
		// RFC5869: no salt => 32 bytes to zero
		uint8_t zero_salt[CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES] = {0};
		const uint8_t *kptr;
		uint32_t klen;

		if (salt && salt->ptr && salt->len)
		{
			kptr = salt->ptr;
			klen = (uint32_t)salt->len;
		}
		else
		{
			kptr = zero_salt;
			klen = CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES; // 32
		}

		CRYS_HMACUserContext_t ctx;
		CRYS_HASH_Result_t mac_words; // uint32_t[CRYS_HASH_RESULT_SIZE_IN_WORDS]
		CRYSError_t rc;

		cc310_hw_acquire();

		// HMAC-SHA256 with key = salt (or 32x00)
		rc = CRYS_HMAC_Init(&ctx, CRYS_HASH_SHA256_mode, (uint8_t *)kptr, klen);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_extract] Init failed: 0x%08X\n", rc);
			rc = sha_failed;
			goto exit;
		}

		rc = CRYS_HMAC_Update(&ctx, ikm->ptr, (uint32_t)ikm->len);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_extract] Update failed: 0x%08X\n", rc);
			rc = sha_failed;
			goto exit;
		}

		// * Finish has 2 args and the second is CRYS_HASH_Result_t (not uint8_t*)
		rc = CRYS_HMAC_Finish(&ctx, mac_words);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_extract] Finish failed: 0x%08X\n", rc);
			rc = sha_failed;
			goto exit;
		}

		// Copy PRK = HMAC-SHA256(salt, IKM) (32 bytes) to 'out'
		memcpy(out, (const uint8_t *)mac_words, CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES);

		rc = ok;
	exit:
		cc310_hw_release();
		memset(&ctx, 0, sizeof(ctx));
		memset(mac_words, 0, sizeof(mac_words));

		if (rc == ok)
			PRINTF("[CC310][hkdf_extract] Completed successfully\n");

		return rc;
	}

#elif MBEDTLS

	// #ifdef MBEDTLS

	// PRINTF("crypto_wrapper.c entra mbedtls hkdf_extract\n");

	psa_algorithm_t psa_alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);

	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, psa_alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

	if (salt->ptr && salt->len)
	{
		TRY_EXPECT_PSA(
		    psa_import_key(&attr, salt->ptr, salt->len, &key_id),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
	}
	else
	{
		uint8_t zero_salt[32] = {0};

		TRY_EXPECT_PSA(psa_import_key(&attr, zero_salt, 32, &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
	}
	size_t out_len;
	TRY_EXPECT_PSA(psa_mac_compute(key_id, psa_alg, ikm->ptr, ikm->len, out,
				       32, &out_len),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
#endif
	return ok;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
	if (alg != SHA_256)
	{
		return crypto_operation_not_implemented;
	}
	/* "N = ceil(L/HashLen)" */
	uint32_t iterations = (out->len + 31) / 32;
	/* "L length of output keying material in octets (<= 255*HashLen)"*/
	if (iterations > 255)
	{
		return hkdf_failed;
	}

#ifdef TINYCRYPT
	uint8_t t[32] = {0};
	struct tc_hmac_state_struct h;
	for (uint8_t i = 1; i <= iterations; i++)
	{
		memset(&h, 0x00, sizeof(h));
		TRY_EXPECT(tc_hmac_set_key(&h, prk->ptr, prk->len), 1);
		tc_hmac_init(&h);
		if (i > 1)
		{
			TRY_EXPECT(tc_hmac_update(&h, t, 32), 1);
		}
		TRY_EXPECT(tc_hmac_update(&h, info->ptr, info->len), 1);
		TRY_EXPECT(tc_hmac_update(&h, &i, 1), 1);
		TRY_EXPECT(tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &h), 1);
		if (out->len < i * 32)
		{
			memcpy(&out->ptr[(i - 1) * 32], t, out->len % 32);
		}
		else
		{
			memcpy(&out->ptr[(i - 1) * 32], t, 32);
		}
	}
#endif

#ifdef CC310

	if (alg != SHA_256)
	{
		return crypto_operation_not_implemented;
	}

	CRYS_HMACUserContext_t ctx;
	CRYSError_t rc;
	uint8_t T[CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES] = {0}; // 32 bytes
	CRYS_HASH_Result_t mac_words;				// aligned buffer used in Finish

	if (!out || !out->ptr)
	{
		PRINTF("[CC310][hkdf_expand] Invalid output buffer\n");
		return hkdf_failed;
	}

	// N = ceil(L/HashLen) with HashLen=32 for SHA-256
	uint32_t iters = (out->len + 31u) / 32u;
	if (iters == 0)
	{
		return ok; // nothing to generate
	}

	if (iters > 255u)
	{
		PRINTF("[CC310][hkdf_expand] Too many blocks (%u)\n", iters);
		return hkdf_failed; // RFC5869: i = 1..255
	}

	cc310_hw_acquire();

	for (uint32_t i = 1; i <= iters; i++)
	{
		// HMAC(PRK, T(i-1) || info || i)
		rc = CRYS_HMAC_Init(&ctx, CRYS_HASH_SHA256_mode,
				    (uint8_t *)prk->ptr, (uint32_t)prk->len);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_expand] Init failed: 0x%08X\n", rc);
			rc = hkdf_failed;
			goto exit;
		}

		if (i > 1)
		{
			rc = CRYS_HMAC_Update(&ctx, T, (uint32_t)sizeof(T));
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][hkdf_expand] Update failed: 0x%08X\n", rc);
				rc = hkdf_failed;
				goto exit;
			}
		}

		if (info && info->ptr && info->len)
		{
			rc = CRYS_HMAC_Update(&ctx, info->ptr, (uint32_t)info->len);
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][hkdf_expand] Update failed: 0x%08X\n", rc);
				rc = hkdf_failed;
				goto exit;
			}
		}

		uint8_t ctr = (uint8_t)i;
		rc = CRYS_HMAC_Update(&ctx, &ctr, 1u);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_expand] Update failed: 0x%08X\n", rc);
			rc = hkdf_failed;
			goto exit;
		}

		// Finish: write digest in mac_words; copy to T (bytes)
		rc = CRYS_HMAC_Finish(&ctx, mac_words);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][hkdf_expand] Finish failed: 0x%08X\n", rc);
			rc = hkdf_failed;
			goto exit;
		}

		memcpy(T, (const uint8_t *)mac_words, sizeof(T));

		// Copy to out respecting total length
		uint8_t *dest = out->ptr + ((i - 1u) * 32u);
		uint32_t remain = out->len - ((i - 1u) * 32u);
		uint32_t chunk = (remain < 32u) ? remain : 32u;
		memcpy(dest, T, chunk);
	}

	rc = ok;

exit:
	cc310_hw_release();
	memset(&ctx, 0, sizeof(ctx));
	memset(mac_words, 0, sizeof(mac_words));
	memset(T, 0, sizeof(T));

	if (rc == ok)
		PRINTF("[CC310][hkdf_expand] Completed successfully\n");

	return rc;

#elif MBEDTLS

	// PRINTF("crypto_wrapper.c entra hkdf_mbedtls expand\n");

	psa_status_t status;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
	PRINTF("key_id: %d\n", key_id);

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

	PRINT_ARRAY("PRK:", prk->ptr, prk->len);
	TRY_EXPECT_PSA(psa_import_key(&attr, prk->ptr, prk->len, &key_id),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	size_t combo_len = (32 + (size_t)info->len + 1);

	TRY_EXPECT_PSA(check_buffer_size(INFO_MAX_SIZE + 32 + 1,
					 (uint32_t)combo_len),
		       ok, key_id, unexpected_result_from_ext_lib);

	uint8_t combo[INFO_MAX_SIZE + 32 + 1];
	uint8_t tmp_out[32];
	memset(tmp_out, 0, 32);
	memcpy(combo + 32, info->ptr, info->len);
	size_t offset = 32;
	for (uint32_t i = 1; i <= iterations; i++)
	{
		memcpy(combo, tmp_out, 32);
		combo[combo_len - 1] = (uint8_t)i;
		size_t tmp_out_len;
		status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
					 combo + offset, combo_len - offset,
					 tmp_out, 32, &tmp_out_len);
		TRY_EXPECT_PSA(status, PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		offset = 0;
		uint8_t *dest = out->ptr + ((i - 1) << 5);
		if (out->len < (uint32_t)(i << 5))
		{
			memcpy(dest, tmp_out, out->len & 31);
		}
		else
		{
			memcpy(dest, tmp_out, 32);
		}
	}
	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
#endif
	return ok;
}

enum err WEAK hkdf_sha_256(struct byte_array *master_secret,
			   struct byte_array *master_salt,
			   struct byte_array *info, struct byte_array *out)
{
	BYTE_ARRAY_NEW(prk, HASH_SIZE, HASH_SIZE);
	TRY(hkdf_extract(SHA_256, master_salt, master_secret, prk.ptr));
	TRY(hkdf_expand(SHA_256, &prk, info, out));
	return ok;
}

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
	for (uint32_t i = 0; i < edhoc_crypto_mock_cb.aead_in_out_count; i++)
	{
		struct edhoc_mock_aead_in_out *predefined_in_out =
		    edhoc_crypto_mock_cb.aead_in_out + i;
		if (aead_mock_args_match_predefined(
			predefined_in_out, key->ptr, key->len, nonce->ptr, nonce->len,
			aad->ptr, aad->len, tag->ptr, tag->len))
		{
			memcpy(out->ptr, predefined_in_out->out.ptr,
			       predefined_in_out->out.len);
			return ok;
		}
	}
#endif

#if defined(TINYCRYPT)
/* (Sin cambios aquí) */
#elif defined(CC310)

	size_t key_len = (size_t)key->len;
	size_t nonce_len = (size_t)nonce->len;
	size_t aad_len = aad ? (size_t)aad->len : 0;
	size_t in_len = (size_t)in->len;
	size_t tag_len = (size_t)tag->len;

	if (!(key_len == 16 || key_len == 24 || key_len == 32))
	{
		PRINTF("AEAD:CC310 invalid key len=%u\n", (unsigned)key_len);
		return unexpected_result_from_ext_lib;
	}
	if (nonce_len < 7 || nonce_len > 13)
	{
		PRINTF("AEAD:CC310 invalid nonce len=%u\n", (unsigned)nonce_len);
		return unexpected_result_from_ext_lib;
	}
	if (tag_len < 4 || tag_len > 16 || (tag_len & 1))
	{
		PRINTF("AEAD:CC310 invalid tag len=%u (must be 4,6,8,10,12,14,16)\n", (unsigned)tag_len);
		return unexpected_result_from_ext_lib;
	}

	if (op == DECRYPT)
	{
		// in = CT || TAG, out = PT
		if (in_len < tag_len)
		{
			PRINTF("AEAD:DEC input too small: in.len=%u tag=%u\n",
			       (unsigned)in_len, (unsigned)tag_len);
			return unexpected_result_from_ext_lib;
		}

		size_t ct_len = in_len - tag_len;
		if (out->len < ct_len)
		{
			PRINTF("AEAD:DEC buffer too small: out.len=%u need=%u\n",
			       (unsigned)out->len, (unsigned)ct_len);
			return buffer_to_small;
		}

		struct byte_array in_ct = {.ptr = in->ptr, .len = (uint32_t)ct_len};
		struct byte_array in_tag = {.ptr = in->ptr + ct_len, .len = (uint32_t)tag_len};
		struct byte_array pt = {.ptr = out->ptr, .len = (uint32_t)ct_len};

		PRINTF("AEAD:DEC  key=%u nonce=%u aad=%u in=%u(out=%u) tag=%u\n",
		       (unsigned)key_len, (unsigned)nonce_len, (unsigned)aad_len,
		       (unsigned)in_len, (unsigned)ct_len, (unsigned)tag_len);

		// Case 1: MAC-only (ciphertext_4: CT=0, AG=8/…): relabel and compare
		if (ct_len == 0)
		{
			PRINTF("DEBUG: Entering AEAD MAC-only case (CT=0)\n");
			uint8_t calc_tag_buf[16]; // tag <= 16, already validated
			struct byte_array empty = {.ptr = NULL, .len = 0};
			struct byte_array calc_tag = {.ptr = calc_tag_buf, .len = (uint32_t)tag_len};

			cc310_hw_acquire();
			// CCM MAC-only: ENCRYPT with PT empty generates expected tag
			int rc = cc310_ccm_auth_crypt(ENCRYPT, key, nonce, aad, &empty, &empty, &calc_tag);
			cc310_hw_release();
			if (rc != 0)
			{
				PRINTF("AEAD:DEC(CT=0) CC310 re-tag rc=%d\n", rc);
				return unexpected_result_from_ext_lib;
			}

			PRINTF("TAG(rx): ");
			for (size_t i = 0; i < tag_len; i++)
				PRINTF("%02X ", in_tag.ptr[i]);
			PRINTF("\n");
			PRINTF("TAG(calc): ");
			for (size_t i = 0; i < tag_len; i++)
				PRINTF("%02X ", calc_tag_buf[i]);
			PRINTF("\n");

			if (ct_memeq_ret0(calc_tag_buf, in_tag.ptr, tag_len) != 0)
			{
				PRINTF("AEAD:DEC(CT=0) tag mismatch\n");
				return unexpected_result_from_ext_lib;
			}

			// PT empty
			return ok;
		}

		// Case 2: CT>0, DEC with HW verification
		cc310_hw_acquire();
		int rc = cc310_ccm_auth_crypt(DECRYPT, key, nonce, aad, &in_ct, &pt, &in_tag);
		cc310_hw_release();

		PRINTF("AEAD:DEC CC310 ret=%d\n", rc);
		return (rc == 0) ? ok : unexpected_result_from_ext_lib;
	}

	else
	{ // ENCRYPT
		size_t in_len = (size_t)in->len;
		size_t tag_len = (size_t)tag->len;

		if (out->len < in_len)
		{
			PRINTF("AEAD:ENC buffer too small for CT: out.len=%u need=%u\n",
			       (unsigned)out->len, (unsigned)in_len);
			return buffer_to_small;
		}
		if (!tag || !tag->ptr || tag_len == 0)
		{
			PRINTF("AEAD:ENC invalid tag buffer (ptr/len)\n");
			return unexpected_result_from_ext_lib;
		}

		struct byte_array ct = {.ptr = out->ptr, .len = (uint32_t)in_len};

		PRINTF("AEAD:ENC key=%u nonce=%u aad=%u in=%u out_cap=%u tag=%u\n",
		       (unsigned)key->len, (unsigned)nonce->len, (unsigned)(aad ? aad->len : 0),
		       (unsigned)in_len, (unsigned)out->len, (unsigned)tag_len);

		cc310_hw_acquire();
		int rc = cc310_ccm_auth_crypt(ENCRYPT, key, nonce, aad, in, &ct, tag);
		cc310_hw_release();
		PRINTF("AEAD:ENC CC310 ret=%d\n", rc);
		if (rc != 0)
			return unexpected_result_from_ext_lib;

		// PSA-like: write TAG following CT
		memcpy(out->ptr + in_len, tag->ptr, tag_len);
		out->len = (uint32_t)(in_len + tag_len);

		// * KEY FIX
		//   Mark the tag as "consumed" to prevent the upper layer from appending it again.
		//   Leave tag->ptr pointing to the end of out (useful for logging), but with len=0. */
		tag->ptr = out->ptr + in_len;
		tag->len = 0;

		if (in_len >= 8)
		{
			PRINTF("CT tail: ");
			for (size_t i = in_len - 8; i < in_len; i++)
				PRINTF("%02X ", out->ptr[i]);
			PRINTF("\n");
		}
		PRINTF("TAG (in out tail): ");
		for (size_t i = 0; i < (size_t)8; i++)
			PRINTF("%02X ", out->ptr[in_len + i]);
		PRINTF("\n");
		PRINTF("AEAD:ENC produced CT||TAG (len=%u)\n", (unsigned)out->len);

		return ok;
	}

#elif defined(MBEDTLS)

	PRINTF("crypto_wrapper.c entra aead mbedtls aead\n");
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(
	    PSA_ALG_CCM, (uint32_t)tag->len);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attr,
				PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, ((size_t)key->len << 3));
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	TRY_EXPECT_PSA(psa_import_key(&attr, key->ptr, key->len, &key_id),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	PRINTF("crypto_wrapper.c entra aead mbedtls aead 1\n");
	if (op == DECRYPT)
	{
		size_t out_len_re = 0;
		PRINTF("crypto_wrapper.c entra aead mbedtls aead decrypt\n");

		PRINTF("[DEBUG MBEDTLS] in (len=%u) before psa_aead_decrypt:\n", in->len);
		for (uint32_t i = 0; i < in->len; i++)
			PRINTF("%02X ", in->ptr[i]);
		PRINTF("\n");

		TRY_EXPECT_PSA(
		    psa_aead_decrypt(key_id, alg, nonce->ptr, nonce->len,
				     aad->ptr, aad->len, in->ptr, in->len,
				     out->ptr, out->len, &out_len_re),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
	}
	else
	{
		PRINTF("crypto_wrapper.c entra aead mbedtls aead encrypt\n");
		size_t out_len_re;
		TRY_EXPECT_PSA(
		    psa_aead_encrypt(key_id, alg, nonce->ptr, nonce->len,
				     aad->ptr, aad->len, in->ptr, in->len,
				     out->ptr, (size_t)(in->len + tag->len),
				     &out_len_re),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

		memcpy(tag->ptr, out->ptr + out_len_re - tag->len, tag->len);

		PRINTF("[DEBUG MBEDTLS] tag (len=%u) after psa_aead_encrypt:\n", tag->len);
		for (uint32_t i = 0; i < tag->len; i++)
			PRINTF("%02X ", tag->ptr[i]);
		PRINTF("\n");
	}
	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
#endif

	return ok;
}

#ifdef TINYCRYPT
/* Declaration of function from TinyCrypt ecc.c */
uECC_word_t cond_set(uECC_word_t p_true, uECC_word_t p_false,
		     unsigned int cond);

/* From uECC project embedded in TinyCrypt - ecc.c
   BSD-2-Clause license */
static uECC_word_t uECC_vli_add(uECC_word_t *result, const uECC_word_t *left,
				const uECC_word_t *right, wordcount_t num_words)
{
	uECC_word_t carry = 0U;
	wordcount_t i;
	for (i = 0; i < num_words; ++i)
	{
		uECC_word_t sum = left[i] + right[i] + carry;
		uECC_word_t val = (sum < left[i]);
		carry = cond_set(val, carry, (sum != left[i]));
		result[i] = sum;
	}
	return carry;
}

/* From uECC project; curve-specific.inc */
/* Calculates EC square root of bignum (Very Large Integer) based on curve */
static void mod_sqrt_default(uECC_word_t *a, uECC_Curve curve)
{
	bitcount_t i;
	uECC_word_t p1[NUM_ECC_WORDS] = {1};
	uECC_word_t l_result[NUM_ECC_WORDS] = {1};
	wordcount_t num_words = curve->num_words;

	/* When curve->p == 3 (mod 4), we can compute
       sqrt(a) = a^((curve->p + 1) / 4) (mod curve->p). */
	uECC_vli_add(p1, curve->p, p1, num_words); /* p1 = curve_p + 1 */
	for (i = uECC_vli_numBits(p1, num_words) - 1; i > 1; --i)
	{
		uECC_vli_modMult_fast(l_result, l_result, l_result, curve);
		if (uECC_vli_testBit(p1, i))
		{
			uECC_vli_modMult_fast(l_result, l_result, a, curve);
		}
	}
	uECC_vli_set(a, l_result, num_words);
}

/**
 * @brief Decompresses an elliptic curve point.
 *
 *
 * @param compressed the compressed key
 * @param public_key the uncopressed key
 * @param curve elliptic curve group point
 */
/* From uECC project
   BSD-2-Clause license */
static inline void uECC_decompress(const uint8_t *compressed,
				   uint8_t *public_key, uECC_Curve curve)
{
	uECC_word_t point[NUM_ECC_WORDS * 2];

	uECC_word_t *y = point + curve->num_words;

	uECC_vli_bytesToNative(point, compressed, curve->num_bytes);

	curve->x_side(y, point, curve);
	mod_sqrt_default(y, curve);

	if ((y[0] & 0x01) != (compressed[0] == 0x03))
	{
		uECC_vli_sub(y, curve->p, y, curve->num_words);
	}

	uECC_vli_nativeToBytes(public_key, curve->num_bytes, point);
	uECC_vli_nativeToBytes(public_key + curve->num_bytes, curve->num_bytes,
			       y);
}
#endif

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
static bool
aead_mock_args_match_predefined(struct edhoc_mock_aead_in_out *predefined,
				const uint8_t *key, const uint16_t key_len,
				uint8_t *nonce, const uint16_t nonce_len,
				const uint8_t *aad, const uint16_t aad_len,
				uint8_t *tag, const uint16_t tag_len)
{
	return array_equals(&predefined->key,
			    &(struct byte_array){.ptr = (void *)key,
						 .len = key_len}) &&
	       array_equals(&predefined->nonce,
			    &(struct byte_array){.ptr = nonce,
						 .len = nonce_len}) &&
	       array_equals(&predefined->aad,
			    &(struct byte_array){.ptr = (void *)aad,
						 .len = aad_len}) &&
	       array_equals(&predefined->tag,
			    &(struct byte_array){.ptr = tag, .len = tag_len});
}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
static bool
sign_mock_args_match_predefined(struct edhoc_mock_sign_in_out *predefined,
				const uint8_t *sk, const size_t sk_len,
				const uint8_t *pk, const size_t pk_len,
				const uint8_t *msg, const size_t msg_len)
{
	return array_equals(&predefined->sk,
			    &(struct byte_array){.len = sk_len,
						 .ptr = (void *)sk}) &&
	       array_equals(&predefined->pk,
			    &(struct byte_array){.len = pk_len,
						 .ptr = (void *)pk}) &&
	       array_equals(&predefined->msg,
			    &(struct byte_array){.len = msg_len,
						 .ptr = (void *)msg});
}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

enum err WEAK sign(enum sign_alg alg, const struct byte_array *sk,
		   const struct byte_array *pk, const struct byte_array *msg,
		   uint8_t *out)
{
#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
	for (uint32_t i = 0; i < edhoc_crypto_mock_cb.sign_in_out_count; i++)
	{
		struct edhoc_mock_sign_in_out *predefined_in_out =
		    edhoc_crypto_mock_cb.sign_in_out + i;
		if (sign_mock_args_match_predefined(predefined_in_out, sk->ptr,
						    sk->len, pk->ptr, PK_SIZE,
						    msg->ptr, msg->len))
		{
			memcpy(out, predefined_in_out->out.ptr,
			       predefined_in_out->out.len);
			return ok;
		}
	}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

	if (alg == EdDSA)
	{
#if defined(COMPACT25519)
		edsign_sign(out, pk->ptr, sk->ptr, msg->ptr, msg->len);
		return ok;
#endif
	}
	else if (alg == ES256)
	{
#if defined(TINYCRYPT)

		uECC_Curve p256 = uECC_secp256r1();
		struct tc_sha256_state_struct ctx_sha256;
		uint8_t hash[NUM_ECC_BYTES];

		TRY_EXPECT(tc_sha256_init(&ctx_sha256), 1);
		TRY_EXPECT(tc_sha256_update(&ctx_sha256, msg->ptr, msg->len),
			   1);
		TRY_EXPECT(tc_sha256_final(hash, &ctx_sha256), 1);

		TRY_EXPECT(uECC_sign(sk->ptr, hash, NUM_ECC_BYTES, out, p256),
			   TC_CRYPTO_SUCCESS);

		return ok;

#elif defined(CC310)
		// ECDSA P-256 with SHA-256, RAW r||s output (64 bytes) as used by PSA
		if (alg != ES256)
			return unsupported_ecdh_curve;

		// Raw private key: 32-byte big-endian (secp256r1)
		if (!sk || !sk->ptr || sk->len != 32)
		{
			PRINTF("[CC310][sign] Invalid private key length\n");
			return sign_failed;
		}

		if (!msg || !msg->ptr)
		{
			PRINTF("[CC310][sign] Invalid message buffer\n");
			return sign_failed;
		}

		if (!out)
		{
			PRINTF("[CC310][sign] Invalid output buffer\n");
			return sign_failed;
		}

		cc310_hw_acquire(); // enables HFCLK + CRYPTOCELL + SaSi_LibInit (on this platform)

		CRYSError_t rc;

		// P-256 domain required by BuildPrivKey in CC310 0.9.13
		const CRYS_ECPKI_Domain_t *p256 =
		    CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);

		if (p256 == NULL)
		{
			PRINTF("[CC310][sign] Failed to get P-256 domain\n");
			rc = sign_failed;
			goto exit;
		}

		// Build the private key structure
		CRYS_ECPKI_UserPrivKey_t user_priv;
		CRYS_ECDSA_SignUserContext_t sign_ctx;
		const CRYS_ECPKI_HASH_OpMode_t hash_mode = CRYS_ECPKI_HASH_SHA256_mode;
		// const CRYS_ECPKI_HASH_OpMode_t hash_mode = CRYS_ECPKI_AFTER_HASH_SHA256_mode;

		rc = CRYS_ECPKI_BuildPrivKey(
		    p256,
		    (const uint8_t *)sk->ptr, (uint32_t)sk->len,
		    &user_priv);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][sign] BuildPrivKey failed: 0x%08X\n", rc);
			rc = sign_failed;
			goto exit;
		}

		// CC310 0.9.13 returns the signature in a buffer (usually DER)
		uint8_t sig_der[80] = {0}; // large enough for DER P-256
		uint32_t sig_der_len = sizeof(sig_der);

		rc = CRYS_ECDSA_Sign(&g_cc310_rnd_state,
				     (SaSiRndGenerateVectWorkFunc_t)CRYS_RND_GenerateVector, // some SDKs use this alias
				     &sign_ctx,
				     &user_priv,
				     hash_mode,
				     (uint8_t *)msg->ptr, (uint32_t)msg->len,
				     sig_der, &sig_der_len);

		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][sign] Sign failed: 0x%08X\n", rc);
			rc = sign_failed;
			return sign_failed;
		}

		// Normalize to r||s (64 bytes) exactly as PSA expects
		if (sig_der_len == 64)
		{
			memcpy(out, sig_der, 64);
		}
		else
		{
			if (der_to_rs64(sig_der, sig_der_len, out) != 0)
			{
				PRINTF("[CC310][sign] DER-to-r||s conversion failed\n");
				rc = sign_failed;
				goto exit;
			}
		}

		rc = ok;
	exit:
		cc310_hw_release();

		// Clean sensitive structures
		memset(&user_priv, 0, sizeof(user_priv));
		memset(&sign_ctx, 0, sizeof(sign_ctx));

		memset(sig_der, 0, sizeof(sig_der));

		if (rc == ok)
			PRINTF("[CC310][sign] Completed successfully\n");

		return rc;

#elif defined(MBEDTLS)
		// PRINTF("crypto_wrapper.c entra sign mbedtls\n");
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

		psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
		bits = PSA_BYTES_TO_BITS((size_t)sk->len);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_VERIFY_MESSAGE |
					    PSA_KEY_USAGE_VERIFY_HASH |
					    PSA_KEY_USAGE_SIGN_MESSAGE |
					    PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						  PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

		TRY_EXPECT_PSA(
		    psa_import_key(&attributes, sk->ptr, sk->len, &key_id),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

		size_t signature_length;
		TRY_EXPECT_PSA(psa_sign_message(key_id, psa_alg, msg->ptr,
						msg->len, out, SIGNATURE_SIZE,
						&signature_length),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		TRY_EXPECT_PSA(signature_length, SIGNATURE_SIZE, key_id,
			       sign_failed);
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		return ok;
#endif
	}
	return unsupported_ecdh_curve;
}

enum err WEAK verify(enum sign_alg alg, const struct byte_array *pk,
		     struct const_byte_array *msg, struct const_byte_array *sgn,
		     bool *result)
{
	if (alg == EdDSA)
	{
#ifdef COMPACT25519
		int verified =
		    edsign_verify(sgn->ptr, pk->ptr, msg->ptr, msg->len);
		if (verified)
		{
			*result = true;
		}
		else
		{
			*result = false;
		}
		return ok;
#endif
	}
	if (alg == ES256)
	{

#if defined(CC310)
		*result = false;

		// Normalize signature to r||s (64) and, if present, DER
		uint8_t sig_rs[64] = {0};
		uint8_t sig_der[80] = {0};
		uint32_t sig_der_len = 0;
		bool have_rs = false;
		bool have_der = false;

		// Case 1: Already r||s (64 bytes)
		if (sgn->len == 64)
		{
			memcpy(sig_rs, sgn->ptr, 64);
			have_rs = true;

			size_t dlen = 0;
			if (rs64_to_der(sig_rs, sig_der, &dlen) == 0)
			{
				sig_der_len = (uint32_t)dlen;
				have_der = true;
			}
		}
		// Case 2: DER (minimal validation: tag 0x30 and size <= buffer)
		else if (sgn->len >= 8 && sgn->ptr[0] == 0x30 && sgn->len <= sizeof(sig_der))
		{
			memcpy(sig_der, sgn->ptr, sgn->len);
			sig_der_len = (uint32_t)sgn->len;
			have_der = true;

			if (der_to_rs64(sig_der, sig_der_len, sig_rs) == 0)
				have_rs = true;
		}
		else
		{
			// Not a valid or expected signature format, but not an error
			return ok;
		}

		// Public key: 65 (0x04||X||Y) or 64 (X||Y)
		if (!pk || !pk->ptr)
		{
			PRINTF("[CC310][verify] Invalid public key buffer\n");
			return ok;
		}

		const uint8_t *X = NULL, *Y = NULL;
		if (pk->len == 65 && pk->ptr[0] == 0x04)
		{
			X = pk->ptr + 1;
			Y = pk->ptr + 33;
		}
		else if (pk->len == 64)
		{
			X = pk->ptr;
			Y = pk->ptr + 32;
		}
		else
		{
			return ok;
		}

		uint8_t pub65[65];
		pub65[0] = 0x04;
		memcpy(pub65 + 1, X, 32);
		memcpy(pub65 + 33, Y, 32);

		cc310_hw_acquire();

		CRYSError_t rc;

		const CRYS_ECPKI_Domain_t *p256 = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
		if (!p256)
		{
			PRINTF("[CC310][verify] Failed to get P-256 domain\n");
			rc = ok; // Verification is simply false, not fatal
			goto exit;
		}

		CRYS_ECPKI_UserPublKey_t user_pub;
		CRYS_ECDSA_VerifyUserContext_t vctx;

		// Build public key with 65B format
		rc = CRYS_ECPKI_BuildPublKey(p256, pub65, sizeof(pub65), &user_pub);
		if (rc != CRYS_OK)
		{
			// Retry with 64B format if needed
			uint8_t pub64[64];
			memcpy(pub64, X, 32);
			memcpy(pub64 + 32, Y, 32);
			rc = CRYS_ECPKI_BuildPublKey(p256, pub64, sizeof(pub64), &user_pub);
			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][verify] BuildPublKey failed\n");
				rc = ok; // Verification fails, but not an error
				goto exit;
			}
		}

		// * Signature first, then message

		// Attempt 1: r||s (64 bytes)
		if (have_rs)
		{
			rc = CRYS_ECDSA_Verify(&vctx, &user_pub,
					       CRYS_ECPKI_HASH_SHA256_mode,
					       sig_rs,	     // signature
					       (uint32_t)64, // length
					       (uint8_t *)msg->ptr,
					       (uint32_t)msg->len);
			// PRINTF("Verify(RS,64) rc=0x%08X\n", (unsigned)rc);
			if (rc == CRYS_OK)
			{
				*result = true;
				rc = ok;
				goto exit;
			}
		}

		// Attempt 2: DER
		if (have_der)
		{
			rc = CRYS_ECDSA_Verify(&vctx, &user_pub,
					       CRYS_ECPKI_HASH_SHA256_mode,
					       sig_der,
					       sig_der_len,
					       (uint8_t *)msg->ptr,
					       (uint32_t)msg->len);
			// PRINTF("Verify(DER,%u) rc=0x%08X\n", (unsigned)sig_der_len, (unsigned)rc);
			if (rc == CRYS_OK)
			{
				*result = true;
				rc = ok;
				goto exit;
			}
		}

		// If neither variant verifies, result remains false
		rc = ok;

	exit:
		cc310_hw_release();

		// Clear sensitive intermediate buffers
		memset(&user_pub, 0, sizeof(user_pub));
		memset(&vctx, 0, sizeof(vctx));
		memset(sig_rs, 0, sizeof(sig_rs));
		memset(sig_der, 0, sizeof(sig_der));

		if (rc == ok && *result)
			PRINTF("[CC310][verify] Completed successfully\n");
		return rc;
#elif defined(MBEDTLS)

		// PRINTF("crypto_wrapper.c entra verify mbedtls \n");
		psa_status_t status;
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

		psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
		bits = PSA_BYTES_TO_BITS(P_256_PRIV_KEY_SIZE);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_VERIFY_MESSAGE |
					    PSA_KEY_USAGE_VERIFY_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(
						  PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);
		TRY_EXPECT_PSA(
		    psa_import_key(&attributes, pk->ptr, pk->len, &key_id),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

		status = psa_verify_message(key_id, psa_alg, msg->ptr, msg->len,
					    sgn->ptr, sgn->len);
		if (PSA_SUCCESS == status)
		{
			*result = true;
		}
		else
		{
			*result = false;
		}
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		return ok;
#elif defined(TINYCRYPT)
		uECC_Curve p256 = uECC_secp256r1();
		struct tc_sha256_state_struct ctx_sha256;
		uint8_t hash[NUM_ECC_BYTES];
		TRY_EXPECT(tc_sha256_init(&ctx_sha256), 1);
		TRY_EXPECT(tc_sha256_update(&ctx_sha256, msg->ptr, msg->len),
			   1);
		TRY_EXPECT(tc_sha256_final(hash, &ctx_sha256), 1);
		uint8_t *pk_ptr = pk->ptr;
		if ((P_256_PUB_KEY_UNCOMPRESSED_SIZE == pk->len) &&
		    (0x04 == *pk->ptr))
		{
			pk_ptr++;
		}
		TRY_EXPECT(uECC_verify(pk_ptr, hash, NUM_ECC_BYTES, sgn->ptr,
				       p256),
			   1);
		*result = true;
		return ok;
#endif
	}
	return crypto_operation_not_implemented;
}

enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
	if (alg == X25519)
	{
#ifdef COMPACT25519
		uint8_t e[F25519_SIZE];
		f25519_copy(e, sk->ptr);
		c25519_prepare(e);
		c25519_smult(shared_secret, pk->ptr, e);
		return ok;
#endif
	}
	if (alg == P256)
	{
#if defined(TINYCRYPT)
		uECC_Curve p256 = uECC_secp256r1();
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		uECC_decompress(pk->ptr, pk_decompressed, p256);

		PRINT_ARRAY("pk_decompressed", pk_decompressed,
			    2 * P_256_PUB_KEY_X_CORD_SIZE);

		TRY_EXPECT(uECC_shared_secret(pk_decompressed, sk->ptr,
					      shared_secret, p256),
			   1);

		return ok;

#elif defined(CC310)

		CRYSError_t rc;
		uint8_t pub65[65] = {0};
		size_t pub_len = 0;

		if (!sk || !sk->ptr || !pk || !pk->ptr)
		{
			PRINTF("[CC310][shared_secret_derive] Invalid input pointers\n");
			return unexpected_result_from_ext_lib;
		}

		// Get P-256 domain
		const CRYS_ECPKI_Domain_t *pDomain = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);

		if (!pDomain)
		{
			PRINTF("[CC310][shared_secret_derive] Failed to get P-256 domain\n");
			return unexpected_result_from_ext_lib;
		}

		// Uncompress pk
		if (pk->len == 65 && pk->ptr[0] == 0x04)
		{
			memcpy(pub65, pk->ptr, 65);
			pub_len = 65;
		}
		// pk 64B (X||Y) transformed into 65B
		else if (pk->len == 64)
		{
			pub65[0] = 0x04;
			memcpy(pub65 + 1, pk->ptr, 32);
			memcpy(pub65 + 33, pk->ptr + 32, 32);
			pub_len = 65;
		}
		else if (pk->len == 33 && (pk->ptr[0] == 0x02 || pk->ptr[0] == 0x03))
		{
			// Compressed form: build and export uncompressed
			CRYS_ECPKI_UserPublKey_t user_pub;
			uint8_t tmp_pub[33];
			uint32_t out_size = sizeof(pub65);

			memcpy(tmp_pub, pk->ptr, 33);

			rc = CRYS_ECPKI_BuildPublKey(pDomain, tmp_pub, sizeof(tmp_pub), &user_pub);

			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][shared_secret_derive] BuildPublKey on compressed pk failed: 0x%08X\n", rc);
				goto exit;
			}

			rc = CRYS_ECPKI_ExportPublKey(&user_pub, CRYS_EC_PointUncompressed, pub65, &out_size);

			if (rc != CRYS_OK || out_size != 65 || pub65[0] != 0x04)
			{
				PRINTF("[CC310][shared_secret_derive] ExportPublKey failed or returned unexpected format\n");
				memset(&tmp_pub, 0, sizeof(tmp_pub));
				goto exit;
			}

			// Clear tmp_pub now that pub65 is populated
			memset(&tmp_pub, 0, sizeof(tmp_pub));
			pub_len = 65;

			// pk compressed (33B) expanded to 65B
		}
		else if (pk->len == 32)
		{
			// X-only (32B). Secret doesn't depend on sign of Y in ECDH. Try prefix 0x02 and then 0x03 if needed
			uint8_t comp[33];
			comp[0] = 0x02;
			memcpy(comp + 1, pk->ptr, 32);

			CRYS_ECPKI_UserPublKey_t tmp_pub;
			uint32_t out_size = sizeof(pub65);

			rc = CRYS_ECPKI_BuildPublKey(pDomain, comp, sizeof(comp), &tmp_pub);

			if (rc != CRYS_OK)
			{
				comp[0] = 0x03;
				rc = CRYS_ECPKI_BuildPublKey(pDomain, comp, sizeof(comp), &tmp_pub);
			}

			if (rc != CRYS_OK)
			{
				PRINTF("[CC310][shared_secret_derive] BuildPublKey from X-only failed: 0x%08X\n", rc);
				goto exit;
			}

			rc = CRYS_ECPKI_ExportPublKey(&tmp_pub, CRYS_EC_PointUncompressed, pub65, &out_size);

			if (rc != CRYS_OK || out_size != 65 || pub65[0] != 0x04)
			{
				PRINTF("[CC310][shared_secret_derive] ExportPublKey from X-only failed or returned unexpected format\n");
				memset(&tmp_pub, 0, sizeof(tmp_pub));
				goto exit;
			}

			memset(&tmp_pub, 0, sizeof(tmp_pub));
			pub_len = 65;
			// pk X-only (32B) expanded to 65B
		}
		else
		{
			PRINTF("[CC310][shared_secret_derive] Unsupported public key format\n");
			return unexpected_result_from_ext_lib;
		}

		cc310_hw_acquire();

		// Private and public key structures
		CRYS_ECPKI_UserPrivKey_t user_priv;
		CRYS_ECPKI_UserPublKey_t user_pub;

		if (!sk->len || sk->len != 32)
		{
			PRINTF("[CC310][shared_secret_derive] Invalid private key length, must be 32B big-endian\n");
			rc = unexpected_result_from_ext_lib;
			goto exit;
		}

		rc = CRYS_ECPKI_BuildPrivKey(
		    pDomain, (uint8_t *)sk->ptr, (uint32_t)sk->len, &user_priv);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][shared_secret_derive] BuildPrivKey failed: 0x%08X\n", rc);
			goto exit;
		}

		rc = CRYS_ECPKI_BuildPublKey(pDomain, pub65, (uint32_t)pub_len, &user_pub);
		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][shared_secret_derive] BuildPublKey failed: 0x%08X\n", rc);
			goto exit;
		}

		// ECDH
		CRYS_ECDH_TempData_t temp;
		uint32_t zz_len = 32; // P-256 32 bytes
		rc = CRYS_ECDH_SVDP_DH(
		    &user_pub,	   // PartnerPublKey_ptr
		    &user_priv,	   // UserPrivKey_ptr
		    shared_secret, // SharedSecretValue
		    &zz_len,	   // in/out length
		    &temp);	   // TempBuff_ptr

		if (rc != CRYS_OK || zz_len != 32)
		{
			PRINTF("[CC310][shared_secret_derive] ECDH_SVDP_DH failed: 0x%08X\n", rc);
			goto exit;
		}

		PRINT_ARRAY("shared_secret", shared_secret, zz_len);
		rc = ok;

	exit:
		cc310_hw_release();

		memset(&user_priv, 0, sizeof(user_priv));
		memset(&user_pub, 0, sizeof(user_pub));
		memset(pub65, 0, sizeof(pub65));

		if (rc == ok)
			PRINTF("[CC310][shared_secret_derive] Completed successfully\n");

		return rc;

#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */

		PRINTF("crypto_wrapper.c entra shared_secret_derive mbedtls \n");
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_status_t result = ok;

		psa_alg = PSA_ALG_ECDH;
		bits = PSA_BYTES_TO_BITS(sk->len);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, psa_alg);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
					    PSA_ECC_FAMILY_SECP_R1));

		TRY_EXPECT_PSA(psa_import_key(&attr, sk->ptr, (size_t)sk->len,
					      &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		psa_key_type_t type = psa_get_key_type(&attr);
		size_t shared_size =
		    PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits);

		size_t shared_secret_len = 0;

		size_t pk_decompressed_len;
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		mbedtls_pk_context ctx_verify = {0};
		mbedtls_pk_init(&ctx_verify);
		if (PSA_SUCCESS !=
		    mbedtls_pk_setup(&ctx_verify, mbedtls_pk_info_from_type(
						      MBEDTLS_PK_ECKEY)))
		{
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
		if (PSA_SUCCESS !=
		    mbedtls_ecp_group_load(&mbedtls_pk_ec(ctx_verify)->grp,
					   MBEDTLS_ECP_DP_SECP256R1))
		{
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
		if (PSA_SUCCESS !=
		    mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp,
					   pk->ptr, pk->len, pk_decompressed,
					   &pk_decompressed_len,
					   sizeof(pk_decompressed)))
		{
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}

		PRINT_ARRAY("pk_decompressed", pk_decompressed,
			    (uint32_t)pk_decompressed_len);

		if (PSA_SUCCESS !=
		    psa_raw_key_agreement(PSA_ALG_ECDH, key_id, pk_decompressed,
					  pk_decompressed_len, shared_secret,
					  shared_size, &shared_secret_len))
		{
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
	cleanup:
		if (PSA_KEY_HANDLE_INIT != key_id)
		{
			TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		}
		mbedtls_pk_free(&ctx_verify);
		return result;
#endif
	}
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	if (alg == X25519)
	{
#ifdef COMPACT25519
		uint8_t extended_seed[32];
#if defined(TINYCRYPT)
		struct tc_sha256_state_struct s;
		TRY_EXPECT(tc_sha256_init(&s), 1);
		TRY_EXPECT(tc_sha256_update(&s, (uint8_t *)&seed, sizeof(seed)),
			   1);
		TRY_EXPECT(tc_sha256_final(extended_seed, &s),
			   TC_CRYPTO_SUCCESS);
#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */
		// PRINTF("crypto_wrapper.c entra ephemeral_dh_key_gen mbedtls compat25519\n");
		size_t length;
		TRY_EXPECT(psa_hash_compute(PSA_ALG_SHA_256, (uint8_t *)&seed,
					    sizeof(seed), sk->ptr, HASH_SIZE,
					    &length),
			   0);
		if (length != 32)
		{
			return sha_failed;
		}
#endif
		compact_x25519_keygen(sk->ptr, pk->ptr, extended_seed);
		pk->len = X25519_KEY_SIZE;
		sk->len = X25519_KEY_SIZE;
#endif
	}
	else if (alg == P256)
	{
#if defined(TINYCRYPT)
		if (P_256_PUB_KEY_X_CORD_SIZE > pk->len)
		{
			return buffer_to_small;
		}
		uECC_Curve p256 = uECC_secp256r1();
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];
		TRY_EXPECT(uECC_make_key(pk_decompressed, sk->ptr, p256),
			   TC_CRYPTO_SUCCESS);
		TRY(_memcpy_s(pk->ptr, P_256_PUB_KEY_X_CORD_SIZE,
			      pk_decompressed, P_256_PUB_KEY_X_CORD_SIZE));
		pk->len = P_256_PUB_KEY_X_CORD_SIZE;
		return ok;

#elif defined(CC310) // CC310 / P-256
		CRYSError_t rc;

		if (!sk || !sk->ptr || !pk || !pk->ptr)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] Invalid sk/pk pointers\n");
			return unexpected_result_from_ext_lib;
		}

		if (sk->len < P_256_PRIV_KEY_SIZE || pk->len < P_256_PUB_KEY_X_CORD_SIZE)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] Buffers too small (sk.len=%u pk.len=%u)\n",
			       (unsigned)sk->len, (unsigned)pk->len);
			return buffer_to_small;
		}

		cc310_hw_acquire();

		const CRYS_ECPKI_Domain_t *p256 =
		    CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
		if (!p256)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] GetEcDomain returned NULL\n");
			rc = unexpected_result_from_ext_lib;
			goto exit;
		}

		CRYS_ECPKI_UserPrivKey_t user_priv;
		CRYS_ECPKI_UserPublKey_t user_pub;
		CRYS_ECPKI_KG_TempData_t kg_temp;
		CRYS_ECPKI_KG_FipsContext_t fips_ctx;

		/* Generate ephemeral key pair */
		rc = CRYS_ECPKI_GenKeyPair(
		    &g_cc310_rnd_state,
		    (SaSiRndGenerateVectWorkFunc_t)CRYS_RND_GenerateVector,
		    p256,
		    &user_priv,
		    &user_pub,
		    &kg_temp,
		    &fips_ctx);

		if (rc != CRYS_OK)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] GenKeyPair failed: 0x%08X\n", rc);
			rc = unexpected_result_from_ext_lib;
			goto exit;
		}

		/* Export public key: SEC1 uncompressed 0x04||X||Y (65 bytes) */
		uint8_t pub_uncompressed[1 + 32 + 32];
		uint32_t pub_len = sizeof(pub_uncompressed);
		rc = CRYS_ECPKI_ExportPublKey(&user_pub,
					      CRYS_EC_PointUncompressed,
					      pub_uncompressed,
					      &pub_len);
		if (rc != CRYS_OK || pub_len != 65 || pub_uncompressed[0] != 0x04)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] ExportPublKey failed: 0x%08X\n", rc);
			rc = unexpected_result_from_ext_lib;
			goto exit;
		}

		// Export private key (32B big-endian)
		uint8_t priv_be[32];
		uint32_t priv_len = sizeof(priv_be);
		rc = CRYS_ECPKI_ExportPrivKey(&user_priv, priv_be, &priv_len);
		if (rc != CRYS_OK || priv_len != 32)
		{
			PRINTF("[CC310][ephemeral_dh_key_gen] ExportPrivKey failed: 0x%08X\n", rc);
			rc = unexpected_result_from_ext_lib;
			goto exit;
		}

		// Populate caller buffers in the expected format:
		//	   - pk: X coordinate (32 bytes)
		//	   - sk: private key (32 bytes, big-endian)
		memcpy(pk->ptr, pub_uncompressed + 1, 32);
		pk->len = 32;

		memcpy(sk->ptr, priv_be, 32);
		sk->len = 32;

		rc = ok;
		PRINT_ARRAY("ephem.sk", sk->ptr, sk->len);
		PRINT_ARRAY("ephem.pk.X", pk->ptr, pk->len);

	exit:
		cc310_hw_release();

		memset(&user_priv, 0, sizeof(user_priv));
		memset(&user_pub, 0, sizeof(user_pub));
		memset(&kg_temp, 0, sizeof(kg_temp));
		memset(&fips_ctx, 0, sizeof(fips_ctx));
		memset(pub_uncompressed, 0, sizeof(pub_uncompressed));
		memset(priv_be, 0, sizeof(priv_be));

		if (rc == ok)
			PRINTF("[CC310][ephemeral_dh_key_gen] Completed successfully\n");
		return rc;

#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */

		// PRINTF("crypto_wrapper.c entra ephemeral_dh_key_gen mbedtls p-256\n");
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_algorithm_t psa_alg = PSA_ALG_ECDH;
		uint8_t priv_key_size = P_256_PRIV_KEY_SIZE;
		size_t bits = PSA_BYTES_TO_BITS((size_t)priv_key_size);
		size_t pub_key_uncompressed_size =
		    P_256_PUB_KEY_UNCOMPRESSED_SIZE;
		uint8_t pub_key_uncompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		if (P_256_PUB_KEY_X_CORD_SIZE > pk->len)
		{
			return buffer_to_small;
		}
		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_EXPORT |
					    PSA_KEY_USAGE_DERIVE |
					    PSA_KEY_USAGE_SIGN_MESSAGE |
					    PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						  PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);

		TRY_EXPECT_PSA(psa_generate_key(&attributes, &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		size_t key_len = 0;
		size_t public_key_len = 0;

		TRY_EXPECT_PSA(psa_export_key(key_id, sk->ptr, priv_key_size,
					      &key_len),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		TRY_EXPECT_PSA(
		    psa_export_public_key(key_id, pub_key_uncompressed,
					  pub_key_uncompressed_size,
					  &public_key_len),
		    PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
		TRY_EXPECT_PSA(public_key_len, P_256_PUB_KEY_UNCOMPRESSED_SIZE,
			       key_id, unexpected_result_from_ext_lib);
		/* Prepare output format - only x parameter */
		memcpy(pk->ptr, (pub_key_uncompressed + 1),
		       P_256_PUB_KEY_X_CORD_SIZE);
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		pk->len = P_256_PUB_KEY_X_CORD_SIZE;
#endif
	}
	else
	{
		return unsupported_ecdh_curve;
	}
	return ok;
}