/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "suites.h"

enum ciphertext { CIPHERTEXT2, CIPHERTEXT3, CIPHERTEXT4 };
enum ciphertext_psk { CIPHERTEXT2_PSK, CIPHERTEXT3A_PSK, CIPHERTEXT3B_PSK };


/**
 * @brief 			Generates a ciphertext.
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4.
 * @param suite 		Cipher suite.
 * @param[in] id_cred 		Id of the credential.
 * @param[in] signature_or_mac 	Signature or a mac byte_array.
 * @param[in] ead 		External authorization data.
 * @param[in] prk 		Pseudo random key.
 * @param[in] th 		Transcript hash.
 * @param[out] ciphertext 	The ciphertext.
 * @param[out] plaintext 	The plaintext. 
 * @return 			Ok or error code. 
 */
enum err ciphertext_gen(enum ciphertext ctxt, struct suite *suite,
			const struct byte_array *c_r,
                        const struct byte_array *id_cred,
			struct byte_array *signature_or_mac,
			const struct byte_array *ead, struct byte_array *prk,
			struct byte_array *th, struct byte_array *ciphertext,
			struct byte_array *plaintext);

/**
 * @brief 			Generates a ciphertext in the PSK version.
 * 
 * @param ctxt 			CIPHERTEXT2_PSK or CIPHERTEXT3A_PSK3.
 * @param suite 		Cipher suite.
 * @param[in] id_cred_psk 		Id of the credential.
 * @param[in] ead 		External authorization data.
 * @param[in] prk 		Pseudo random key.
 * @param[in] th 		Transcript hash.
 * @param[out] ciphertext 	The ciphertext.
 * @param[out] plaintext 	The plaintext. 
 * @return 			Ok or error code. 
 */
enum err ciphertext_gen_psk(enum ciphertext_psk ctxt, struct suite *suite,
			const struct byte_array *c_r,
			const struct byte_array *id_cred_psk, struct byte_array *ciphertext_b,
			const struct byte_array *ead, struct byte_array *prk,
			struct byte_array *th, struct byte_array *ciphertext,
			struct byte_array *plaintext);

/**
 * @brief 			Decrypts a ciphertext and splits the resulting 
 * 				plaintext into its components.
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param suite 		cipher suite
 * @param c_r                   Connection identifier of the responder. 
 *                              Set this to NULL when using with CIPHERTEXT3 
 *                              or CIPHERTEXT4
 * @param[out] id_cred 		Id of the credential.
 * @param[out] signature_or_mac Signature or a mac byte_array.
 * @param[out] ead 		External authorization data.
 * @param[in] prk 		Pseudo random key.
 * @param[in] th 		Transcript hash.
 * @param[in] ciphertext 	The input.
 * @param[out] plaintext 	The plaintext.
 * @return 			Ok or error code.
 */
enum err ciphertext_decrypt_split(
	enum ciphertext ctxt, struct suite *suite, struct byte_array *c_r,
	struct byte_array *id_cred, struct byte_array *sig_or_mac,
	struct byte_array *ead, struct byte_array *prk, struct byte_array *th,
	struct byte_array *ciphertext, struct byte_array *plaintext);

enum err ciphertext_decrypt_split_psk(
	enum ciphertext_psk ctxt, struct suite *suite, struct byte_array *c_r,
	struct byte_array *id_cred_psk, struct byte_array *ciphertext_b,
	struct byte_array *ead, struct byte_array *prk, struct byte_array *th,
	struct byte_array *ciphertext, struct byte_array *plaintext);

#endif
