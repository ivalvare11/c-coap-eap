#include <string.h>

#include "byte_array.h"
#include "eap-edhoc.h"
#include "edhoc.h"
#include "edhoc_internal.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "include.h"
#include "print_util.h"
#include "runtime_context.h"

#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqLength ((struct eap_msg *)eapReqData)->length

/**
 * @brief	Method that skips the flag contained in an EDHOC message
 * @param	msg	Pointer to the EDHOC message whose flag is going to be removed
 * @retval	OK if everything works fine
 */
enum err skip_flag(struct byte_array *msg)
{
	uint8_t flag = msg->ptr[0];

	bool is_bstr = ((flag & 0xE0) == 0X40);

	if (!is_bstr) {
		if (flag == 0x00 || flag == 0x20 || flag == 0x40 || flag == 0x60)
			{
			if (msg->len < 2)
			{
				printf("ERROR: only flags byte present, no CBOR sequence\n");
				return wrong_parameter;
			}

			// * Skip the flag
			msg->ptr++;
			msg->len--;
		} else
			return wrong_parameter;
	}
	return ok;
}

void eap_edhoc_peer_cred_gen(struct cred_array *cred_r_array,
			     struct edhoc_initiator_context *c_i)
{
	struct other_party_cred *cred_r;
	cred_r = (struct other_party_cred *)calloc(1, sizeof(struct other_party_cred));

	// There are several p256_v16 test vectors, choose one (select 5 or 6 for EAP-EDHOC method 3, select 7 for PSK auth).
	uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	// c_i.sock = &sockfd;
	c_i->c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i->c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i->method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i->suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i->suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i->ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i->ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i->ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i->ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i->id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i->id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i->cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i->cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i->g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i->g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i->x.len = test_vectors[vec_num_i].x_raw_len;
	c_i->x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i->g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i->g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i->i.len = test_vectors[vec_num_i].i_raw_len;
	c_i->i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i->sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i->sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i->pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i->pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	if (TEST_VEC_NUM == 7)
	{
		c_i->id_cred_psk.len = test_vectors[vec_num_i].id_cred_psk_len;
		c_i->id_cred_psk.ptr =
			(uint8_t *)test_vectors[vec_num_i].id_cred_psk;
	}

	cred_r->id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r->id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r->cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r->cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r->g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r->g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r->pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r->pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r->ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r->ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r->ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r->ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;

	cred_r_array->len = 1;
	cred_r_array->ptr = cred_r;

	return;
}

struct data_edhoc *initMethodEap_edhoc()
{
	struct data_edhoc *edhoc_data = NULL;
	edhoc_data = (struct data_edhoc *)calloc(1, sizeof(*edhoc_data));
	edhoc_data->state = EDHOC_START;

	edhoc_data->c_i = (struct edhoc_initiator_context *)calloc(1, sizeof(struct edhoc_initiator_context));
	edhoc_data->cred_r_array = (struct cred_array *)calloc(1, sizeof(struct cred_array));
	edhoc_data->rc = (struct runtime_context *)calloc(1, sizeof(struct runtime_context));

	edhoc_data->PRK_exporter.ptr = (uint8_t *)calloc(32, sizeof(uint8_t));
	edhoc_data->PRK_exporter.len = 32;

	edhoc_data->msk.ptr = NULL;
	edhoc_data->msk.len = 0;

	edhoc_data->emsk.ptr = (uint8_t *)calloc(64, sizeof(uint8_t));
	edhoc_data->emsk.len = 64;

	edhoc_data->method_id.ptr = (uint8_t *)calloc(64, sizeof(uint8_t));
	edhoc_data->method_id.len = 64;

	edhoc_data->PRK_out.ptr = (uint8_t *)calloc(32, sizeof(uint8_t));
	edhoc_data->PRK_out.len = 32;

	edhoc_data->err_msg.ptr = NULL;
	edhoc_data->err_msg.len = 0;

	runtime_context_init(edhoc_data->rc);

	edhoc_data->c_r.ptr = (uint8_t *)calloc(C_R_SIZE, sizeof(uint8_t));
	edhoc_data->c_r.len = C_R_SIZE;

	edhoc_data->flags = 0;

	return edhoc_data;
}

uint8_t check_edhoc(const uint8_t *eapReqData)
{
	if (reqMethod == EAP_EDHOC)
		return TRUE;
	return FALSE;
}

void process_edhoc(struct data_edhoc *edhoc_data, const uint8_t *eapReqData,
		   uint8_t *methodState, uint8_t *decision)
{
	const uint8_t *pos = NULL;
	size_t len;
	enum err retval;

	*methodState = MAY_CONT;
	*decision = FAIL;

	if (eapReqData == NULL)
		return;

	len = (size_t)NTOHS(reqLength);
	if (len > sizeof(struct eap_msg))
	{
		pos = eapReqData + sizeof(struct eap_msg);
		len = len - sizeof(struct eap_msg);
	}

	if (edhoc_data->state == EDHOC_START)
	{
		if (len > 0)
		{
			edhoc_data->flags = 0x00;
			pos++;
			len--;
		}

		// * Generation of credentials and MSG1
		eap_edhoc_peer_cred_gen(edhoc_data->cred_r_array, edhoc_data->c_i);

		retval = msg1_gen(edhoc_data->c_i, edhoc_data->rc);
		PRINTF("DEBUG: msg1_gen() returned %d, rc->msg.len=%u\n", retval, edhoc_data->rc->msg.len);

		if (retval != ok)
		{
			PRINTF("The first message could not be generated\n");
			edhoc_data->state = EDHOC_FAILURE;
			return;
		}

		edhoc_data->state = EDHOC_MSG1;
		*decision = COND_SUCC;
		PRINTF("The first message was generated, the session continues...\n");
		return;
	}
	else if (edhoc_data->state == EDHOC_MSG1)
	{
		if (len > 0)
		{
			memcpy(edhoc_data->rc->msg.ptr, pos, len);
			edhoc_data->rc->msg.len = len;
		}

		enum err retflag;
		retflag = skip_flag(&(edhoc_data->rc->msg));

		if (retflag == ok)
			PRINTF("A flag was skipped\n");

		// * Generation of MSG3 when response from MSG2 is received
		retval = msg3_gen(edhoc_data->c_i, edhoc_data->rc, edhoc_data->cred_r_array, &(edhoc_data->c_r), &(edhoc_data->PRK_out));
		if (retval != ok)
		{
			PRINTF("The third message could not be generated\n");
			edhoc_data->state = EDHOC_FAILURE;
			return;
		}

		edhoc_data->state = EDHOC_MSG3;
		*decision = COND_SUCC;
		PRINTF("The third message was generated, the session continues...\n");
		return;
	}
	else if (edhoc_data->state == EDHOC_MSG3)
	{
		if (len > 0)
		{
			memcpy(edhoc_data->rc->msg.ptr, pos, len);
			edhoc_data->rc->msg.len = len;
		}

		enum err retflag;
		retflag = skip_flag(&(edhoc_data->rc->msg));

		if (retflag == ok)
			PRINTF("A flag was skipped\n");

		// * Processing of MSG4
		retval = msg4_process(edhoc_data->rc);
		if (retval != ok)
		{
			PRINTF("The fourth message could not be processed\n");
			edhoc_data->state = EDHOC_FAILURE;
			*decision = FAIL;
			return;
		}

		PRINTF("The fourth message was processed\n");

		// * Derivation of PRK_exporter
		static uint8_t PRK_exporter_buf[32];
		edhoc_data->PRK_exporter.ptr = PRK_exporter_buf;
		edhoc_data->PRK_exporter.len = 32;
		prk_out2exporter(SHA_256, &(edhoc_data->PRK_out), &(edhoc_data->PRK_exporter));

		// * Derivation of MSK
		static uint8_t msk_buf[64];
		edhoc_data->msk.ptr = msk_buf;
		edhoc_data->msk.len = 64;
		edhoc_exporter(SHA_256, 4, &(edhoc_data->PRK_exporter), &(edhoc_data->msk));
		memcpy(msk_key, edhoc_data->msk.ptr, edhoc_data->msk.len);
		PRINTF("The MSK key was successfully copied\n");

		// * Derivation of EMSK
		static uint8_t emsk_buf[64];
		edhoc_data->emsk.ptr = emsk_buf;
		edhoc_data->emsk.len = 64;
		edhoc_exporter(SHA_256, 5, &(edhoc_data->PRK_exporter), &(edhoc_data->emsk));

		// * Derivation of method_id
		static uint8_t method_id_buf[64];
		edhoc_data->method_id.ptr = method_id_buf;
		edhoc_data->method_id.len = 64;
		edhoc_exporter(SHA_256, 6, &(edhoc_data->PRK_exporter), &(edhoc_data->method_id));

		PRINTF("The session finished with SUCCESS\n");

		PRINTF("The PRK exporter is: \n");
		PRINT_ARRAY("PRK_exporter", edhoc_data->PRK_exporter.ptr, edhoc_data->PRK_exporter.len);

		PRINTF("The MSK is: \n");
		PRINT_ARRAY("MSK", edhoc_data->msk.ptr, edhoc_data->msk.len);

		PRINTF("The EMSK is: \n");
		PRINT_ARRAY("EMSK", edhoc_data->emsk.ptr, edhoc_data->emsk.len);

		PRINTF("The Method ID is: \n");
		PRINT_ARRAY("METHOD_ID", edhoc_data->method_id.ptr, edhoc_data->method_id.len);

		edhoc_data->state = EDHOC_SUCCESS;
		*methodState = DONE;
		*decision = COND_SUCC;

		eapKeyAvailable = TRUE;

		return;
	}
	else if (edhoc_data->state == EDHOC_SUCCESS)
	{
		*methodState = DONE;
		*decision = COND_SUCC;
	} else
	{
		*methodState = MAY_CONT;
		*decision = FAIL;
	}
	return;
}

void buildResp_edhoc(struct data_edhoc *edhoc_data, uint8_t *eapRespData, uint8_t reqId)
{
	size_t payload_len = 0;
	const uint8_t *payload_ptr = NULL;

	switch (edhoc_data->state)
	{
		case EDHOC_MSG1:
		case EDHOC_MSG3:
			payload_ptr = edhoc_data->rc->msg.ptr;
			payload_len = edhoc_data->rc->msg.len;
			break;
		case EDHOC_SUCCESS:
			break;
		default:
			payload_ptr = NULL;
			payload_len = 0;
			break;
	}

	// * 1 is for byte of flags
	size_t total_payload = payload_len + 1;

	// * EAP Response message
	struct eap_msg *response = (struct eap_msg *)eapRespData;
	response->code = RESPONSE_CODE;
	response->id = reqId;
	response->length = HTONS((uint16_t)(sizeof(struct eap_msg) + total_payload));
	response->method = EAP_EDHOC;

	uint8_t *ptr = eapRespData + sizeof(struct eap_msg);
	*ptr++ = edhoc_data->flags;
	PRINTF("DEBUG buildResp_edhoc(): wrote flags 0x%02X\n", edhoc_data->flags);

	if (payload_len > 0 && payload_ptr != NULL)
		memcpy(ptr, payload_ptr, payload_len);

	PRINTF("EDHOC state = %d, payload length = %zu\n\n", edhoc_data->state, total_payload);
}
