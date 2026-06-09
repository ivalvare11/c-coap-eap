#include <string.h>

#include "byte_array.h"
#include "crypto_wrapper.h"
#include "include.h"
#include "oscore.h"
#include "oscore_context.h"

/**
 * @brief	Prints the bytes of an array as a chain of hexadecimal values
 * @param	text	Pointer to an array of bytes
 * @param	length	Bytes to be printed from the array
 */
void printf_hex(unsigned char *text, int length)
{
	int i;
	for (i = 0; i < length; i++)
		PRINTF("%02x", text[i]);
	PRINTF("\n");
	return;
}

enum err create_oscore_context(struct context *c_ctx, uint8_t sender_id,
			       uint8_t recipient_id, uint8_t *msk_key)
{
	enum err e;

	PRINTF("The MSK key is: \n");
	printf_hex(msk_key, MSK_LENGTH);

	BYTE_ARRAY_NEW(msk_array, MSK_LENGTH, MSK_LENGTH);
	memcpy(msk_array.ptr, msk_key, MSK_LENGTH);

	// * If neither CS-C nor CS-I was sent (i.e., default algorithms are used), the value used to generate CS will be the same as if the
	// * default algorithms were explicitly sent in CS-C or CS-I (i.e., a CBOR array with the cipher suite value of 0)
	uint8_t cs_bytes[] = { 0x00, 0x00 };
	size_t cs_len = sizeof(cs_bytes);

	// * info_secret = CS || "COAP-EAP OSCORE MASTER SECRET"
	const char *label_secret = "COAP-EAP OSCORE MASTER SECRET";
	size_t info_secret_len = cs_len + strlen(label_secret);
	BYTE_ARRAY_NEW(info_secret, info_secret_len, info_secret_len);
	memcpy(info_secret.ptr, cs_bytes, cs_len);
	memcpy(info_secret.ptr + cs_len, label_secret, strlen(label_secret));

	// * info_salt = CS || "COAP-EAP OSCORE MASTER SALT"
	const char *label_salt = "COAP-EAP OSCORE MASTER SALT";
	size_t info_salt_len = cs_len + strlen(label_salt);
	BYTE_ARRAY_NEW(info_salt, info_salt_len, info_salt_len);
	memcpy(info_salt.ptr, cs_bytes, cs_len);
	memcpy(info_salt.ptr + cs_len, label_salt, strlen(label_salt));

	// * Master secret/salt
	const size_t master_secret_len = 16;
	const size_t master_salt_len = 8;
	BYTE_ARRAY_NEW(oscore_master_secret, master_secret_len, master_secret_len);
	BYTE_ARRAY_NEW(oscore_master_salt, master_salt_len, master_salt_len);

	// * Derivation of the master secret/salt
	e = hkdf_expand(SHA_256, &msk_array, &info_secret, &oscore_master_secret);
	e = hkdf_expand(SHA_256, &msk_array, &info_salt, &oscore_master_salt);

	PRINTF("OSCORE Master Secret (%u bytes): ", oscore_master_secret.len);
	printf_hex(oscore_master_secret.ptr, oscore_master_secret.len);

	PRINTF("OSCORE Master Salt (%u bytes): ", oscore_master_salt.len);
	printf_hex(oscore_master_salt.ptr, oscore_master_salt.len);

	uint8_t sender_id_buf[] = { sender_id };
	uint8_t recipient_id_buf[] = { recipient_id };

	struct oscore_init_params params =
	{
		.master_secret = { .ptr = oscore_master_secret.ptr,	.len = master_secret_len },
		.sender_id = { .ptr = sender_id_buf, .len = sizeof(sender_id_buf) },
		.recipient_id = { .ptr = recipient_id_buf, .len = sizeof(recipient_id_buf) },
		.id_context = { .ptr = NULL, .len = 0 },
		.master_salt = { .ptr = oscore_master_salt.ptr, .len = master_salt_len },
		.aead_alg = AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true
	};

	e = oscore_context_init(&params, c_ctx);
	if (e != ok)
	{
		PRINTF("oscore_context_init failed\n");
		return wrong_parameter;
	}

	PRINTF("OSCORE context successfully initialized\n");
	return ok;
}
