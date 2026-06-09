#ifndef __EAP_EDHOC
#define __EAP_EDHOC

#include "edhoc.h"
#include "eap-peer.h"
#include "runtime_context.h"

struct data_edhoc
{
	enum {
		EDHOC_START,
		EDHOC_MSG1,
		EDHOC_MSG3,
		EDHOC_SUCCESS,
		EDHOC_FAILURE
	} state;
	struct byte_array PRK_exporter;
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array err_msg;

	struct byte_array c_r;

	struct edhoc_initiator_context *c_i;
	struct cred_array *cred_r_array;
	struct runtime_context *rc;

	uint8_t flags;
};

enum err skip_flag(struct byte_array *msg);

uint8_t check_edhoc(const uint8_t *eapReqData);
void process_edhoc(struct data_edhoc *edhoc_data, const uint8_t *eapReqData, uint8_t *methodState, uint8_t *decision);
void buildResp_edhoc(struct data_edhoc *edhoc_data, uint8_t *eapRespData, uint8_t reqId);

struct data_edhoc *initMethodEap_edhoc();

#endif