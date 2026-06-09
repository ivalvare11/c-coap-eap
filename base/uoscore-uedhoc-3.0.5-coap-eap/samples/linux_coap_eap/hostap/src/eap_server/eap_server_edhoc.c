
#include "includes.h"

#include "common.h"
#include "eap_i.h"

#include "edhoc.h"
#include "edhoc_internal.h"
#include "./common/oscore_edhoc_error.h"
#include "../eap_common/eap_edhoc_common.h"
#include "psk_api.h"

struct eap_edhoc_data {
	
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array PRK_exporter;
	struct byte_array err_msg;
	
	enum { START, MSG1_recv, MSG2_send, MSG3_recv, MSG4_send, SUCCESS, FAILURE } state;
	struct byte_array c_i;
	struct edhoc_responder_context c_r;
	struct cred_array cred_i_array;

	struct fragment_buffer_t frag_buffer;
	
	struct runtime_context rc;
};

struct eap_edhoc_data_reverse {
	
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array PRK_exporter;
	struct byte_array err_msg;
	
	enum { MSG1_send, MSG2_recv, MSG3_send, SUCCESS_I, FAILURE_I } state;
	struct byte_array c_r;
	struct edhoc_initiator_context c_i;
	struct cred_array cred_r_array;

	struct fragment_buffer_t frag_buffer;
	
	struct runtime_context rc;
};


static void * eap_edhoc_init(struct eap_sm *sm)
{
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data;
		data = os_zalloc(sizeof(*data));
		if (data == NULL)
			return NULL;
		data->state = START;
		
		data->PRK_exporter.ptr=os_zalloc(32*sizeof(uint8_t));
		data->PRK_exporter.len=32;	
		
		data->msk.ptr=malloc(64*sizeof(uint8_t));
		data->msk.len=64;
	  
	    data->emsk.ptr=os_zalloc(64*sizeof(uint8_t));
		data->emsk.len=64;
		
		data->method_id.ptr=os_zalloc(64*sizeof(uint8_t));
		data->method_id.len=64;
		
		data->PRK_out.ptr=os_zalloc(32*sizeof(uint8_t));
	    data->PRK_out.len=32;

	    data->err_msg.ptr = NULL;
	    data->err_msg.len = 0;

		runtime_context_init(&(data->rc));
		data->c_i.ptr=os_zalloc(C_I_SIZE*sizeof(uint8_t));
		data->c_i.len=C_I_SIZE;
		return data;
	}
	else {
		struct eap_edhoc_data_reverse *data;
		data = os_zalloc(sizeof(*data));
		if (data == NULL)
			return NULL;
		data->state = MSG1_send;
		
		data->PRK_exporter.ptr=os_zalloc(32*sizeof(uint8_t));
		data->PRK_exporter.len=32;	
		
		data->msk.ptr=malloc(64*sizeof(uint8_t));
		data->msk.len=64;
	  
	    data->emsk.ptr=os_zalloc(64*sizeof(uint8_t));
		data->emsk.len=64;
		
		data->method_id.ptr=os_zalloc(64*sizeof(uint8_t));
		data->method_id.len=64;
		
		data->PRK_out.ptr=os_zalloc(32*sizeof(uint8_t));
	    data->PRK_out.len=32;

	    data->err_msg.ptr = NULL;
	    data->err_msg.len = 0;

		runtime_context_init(&(data->rc));
		data->c_r.ptr=os_zalloc(C_R_SIZE*sizeof(uint8_t));
		data->c_r.len=C_R_SIZE;
		return data;
	}
}

static void eap_edhoc_reset(struct eap_sm *sm, void *priv)
{

	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;
		os_free(data->PRK_exporter.ptr);
		os_free(data->msk.ptr);
		os_free(data->emsk.ptr);
		os_free(data->method_id.ptr);
		os_free(data->PRK_out.ptr);
		os_free(data->c_i.ptr);
		os_free(data->cred_i_array.ptr);
		os_free(data);
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;
		os_free(data->PRK_exporter.ptr);
		os_free(data->msk.ptr);
		os_free(data->emsk.ptr);
		os_free(data->method_id.ptr);
		os_free(data->PRK_out.ptr);
		os_free(data->c_r.ptr);
		os_free(data->cred_r_array.ptr);
		os_free(data);
	}
}

static struct wpabuf * send_empty(u8 flags, u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, 1, //len = 1 byte --> flags
				        EAP_CODE_REQUEST, id);
	if (req == NULL) {
		DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
		return NULL;	
	}

	// Copy the content in the created response.
	wpabuf_put_u8(req, flags);
	
	return req;
}

static struct wpabuf * send_msg(fragment_buffer_t *buffer, u8 flags, u8 id)
{
	struct wpabuf *req;

    uint8_t *fragment = (uint8_t *)malloc(MAX_FRAGMENT_SIZE);
    size_t fragment_len;
	
	int retval = get_next_fragment(buffer, fragment, &fragment_len);
	
	if (retval == 0){
		free(fragment);
		return NULL;
	} 
	
	if (retval == 3){ // First fragment of the message. Adding the Length header.

		flags |= EDHOC_L_FLAG;
		flags |= EDHOC_M_FLAG;

       	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, fragment_len + 1 + 4,
				             EAP_CODE_REQUEST, id);
		if (req == NULL) {
			DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
			return NULL;	
		}

		// Copy the content in the created response.
		wpabuf_put_u8(req, flags);

		// Convert the length to network byte order
    	uint32_t network_order_len = htonl(buffer->len);

		wpabuf_put_le32(req, network_order_len);
		wpabuf_put_data(req, fragment, fragment_len);
	}
	else {
		if (retval == 1){ // Adding the M flags in all the fragments except the last one.
			flags |= EDHOC_M_FLAG;
		}

       	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, fragment_len + 1,
				             EAP_CODE_REQUEST, id);
		if (req == NULL) {
			DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
			return NULL;	
		}

		// Copy the content in the created response.
		wpabuf_put_u8(req, flags);
		wpabuf_put_data(req, fragment, fragment_len);
	}

	free(fragment);

	return req;
}

static struct wpabuf * eap_edhoc_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	if (ROLE_SCHEME == 0){

		struct eap_edhoc_data *data = priv;
		u8 flags = 0;

		switch (data->state) {
		case START:
			//Activating the S flag in the Start message.
			flags |= EDHOC_S_FLAG;
			return send_empty(flags, id);
		case MSG1_recv:
		case MSG3_recv:
			return send_empty(flags, id);
		case MSG2_send:
		case MSG4_send:
			return send_msg(&(data->frag_buffer), flags, id);
		default:
			DEBUG_MSG("EAP-EDHOC: Unknown state %d in buildReq",
				   data->state);
			break;
		}
		return NULL;
	}
	else {
		
		struct eap_edhoc_data_reverse *data = priv;
		u8 flags = 0;
		//Activating the V flag to indicate Role-Rev.
		flags |= EDHOC_V_FLAG;

		switch (data->state) {
		case MSG1_send:

			flags |= EDHOC_S_FLAG;

			//the initiator generates its credentials before generating msg1.
			eap_edhoc_peer_cred_gen(&(data->cred_r_array), &(data->c_i));
			
			//Gen MSG1:
			enum err retval = msg1_gen(&(data->c_i), &(data->rc));
			if (retval != ok){
		        	DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
	        		data->state = FAILURE_I;
	        		return NULL; 
			}
		
			// Storing msg1 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			DEBUG_MSG("Gen MSG1:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);
			DEBUG_MSG("");

		case MSG3_send:
			return send_msg(&(data->frag_buffer), flags, id);
		case MSG2_recv:
			return send_empty(flags, id);
		default:
			DEBUG_MSG("EAP-EDHOC: Unknown state %d in buildReq",
				   data->state);
			break;
		}
		return NULL;
	}
}


static void eap_edhoc_process(struct eap_sm *sm, void *priv,
					struct wpabuf *respData)
{
	u8 flags_received = 0;
	u32 msg_total_len = 0;

	const u8 *pos;
	size_t len;
		
	// Parsing the received EAP Request.
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, respData, &len);
	if (pos == NULL || len == 0) {
		DEBUG_MSG("EAP-EDHOC: Invalid frame (pos=%p len=%lu)",
			   pos, (unsigned long) len);
		return;
	}	
		
	DEBUG_MSG("EAP-EDHOC: Received EDHOC Request.");
	
	// Parsing the flags octet.
	flags_received = *pos++;
	len--;

	DEBUG_MSG("EAP-EDHOC: Received flags: %u \n", flags_received);

	// Getting the msg Total Lenght value if present.
	if (flags_received & EDHOC_L_FLAG){
		if (len < 4){
			DEBUG_MSG("EAP-EDHOC: Invalid message: L flag activated but Length field not included.");
			return;
		}

		memcpy(&msg_total_len, pos, 4);
		msg_total_len = ntohl(msg_total_len);  // Convert to host byte order if necessary
		pos+=4;
		len-=4;

		DEBUG_MSG("EAP-EDHOC: Received MSG Total Length: %u \n", msg_total_len);

	}
	else {
		msg_total_len = (u32)len;
	}
	
	// Process message received --> Direct schema, EAP Server = Responder:	
	if (!(flags_received & EDHOC_V_FLAG)) {
		
		if (ROLE_SCHEME == 1){
			DEBUG_MSG("Protocol in Role Reverse mode received a Direct mode msg, abort.");
			return;
		}
		
		struct eap_edhoc_data *data = priv;

		if (data->state == START) {
			
			data->state = MSG1_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);

		}

		if (data->state == MSG1_recv){
			//Receiving MSG1.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG1 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish receiving MSG1, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;
			
			//After receiving MSG1, the responder generates its credentials.
        	eap_edhoc_server_cred_gen(&(data->cred_i_array), &(data->c_r));

			// Once we finish receiving MSG1, we generate and send MSG2.
			data->state = MSG2_send;

			fragment_buffer_free(&(data->frag_buffer));

			/*create message 2*/
			enum err retval = msg2_gen(&(data->c_r), &(data->rc), &(data->c_i));
			if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				return; 
			}
				
			DEBUG_MSG("Gen MSG2:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);
			DEBUG_MSG("");
			
			// Storing MSG2 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			return;
		}
		if (data->state == MSG2_send) {

			// Finish sending MSG2 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish sending MSG2, we receive MSG3.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = MSG3_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);

		}
		if (data->state == MSG3_recv){
			//Receiving MSG3.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG3 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish receiving MSG3, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;

			/*process message 3*/
	    	enum err retval = msg3_process(&(data->c_r), &(data->rc), &(data->cred_i_array), &(data->PRK_out), &NULL_ARRAY);
	    	if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				return; 
			}

			fragment_buffer_free(&(data->frag_buffer));
			
			/*create message 4*/
			enum err retval2 = msg4_gen(&(data->c_r), &(data->rc));
			if (retval2 != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				return; 
			}
			
			DEBUG_MSG("Gen MSG4:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);
			DEBUG_MSG("");

			// Storing MSG4 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			data->state = MSG4_send;
			return;
		}
		
		if (data->state == MSG4_send){

			// Finish sending MSG4 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			fragment_buffer_free(&(data->frag_buffer));

			data->state = SUCCESS;

			// Once we finish sending MSG4, we accomplish the key derivation process.
			DEBUG_MSG("EAP SUCCESS");

			prk_out2exporter(SHA_256, &(data->PRK_out), &(data->PRK_exporter));
			DEBUG_MSG("PRK_exporter");
			DEBUG_PRINT_ARRAY(data->PRK_exporter.ptr, data->PRK_exporter.len);
			
			#ifdef RESUMPTION
			struct byte_array rPSK;
			struct byte_array rKID;

			rPSK.ptr=malloc(16*sizeof(uint8_t));
			rPSK.len=16;

			rKID.ptr=malloc(1*sizeof(uint8_t));
			rKID.len=1;

			edhoc_exporter(SHA_256, rPSK_TAG, &(data->PRK_exporter),
						   &rPSK);
			DEBUG_MSG("rPSK:");
			DEBUG_PRINT_ARRAY(rPSK.ptr, rPSK.len);

			edhoc_exporter(SHA_256, rKID_TAG, &(data->PRK_exporter),
						   &rKID);
			DEBUG_MSG("rKID:");
			DEBUG_PRINT_ARRAY(rKID.ptr, rKID.len);

			//GENERATE CREDS FROM rPSK AND rKID.
			struct byte_array CRED_I_out;
			struct byte_array CRED_R_out;

			CRED_I_out.ptr=malloc(CRED_I_SIZE*sizeof(uint8_t));
			CRED_I_out.len=CRED_I_SIZE;

			CRED_R_out.ptr=malloc(CRED_R_SIZE*sizeof(uint8_t));
			CRED_R_out.len=CRED_R_SIZE;

			generate_CWT_cred("initiator", &rKID, &rPSK, &CRED_I_out);
			PRINT_ARRAY("CRED_I_out: ", CRED_I_out.ptr,
				    CRED_I_out.len);
			generate_CWT_cred("responder", &rKID, &rPSK, &CRED_R_out);
			PRINT_ARRAY("CRED_R_out: ", CRED_R_out.ptr,
				    CRED_R_out.len);

			//Storing RESUMPTION CREDS.
			//store_creds(&rKID, &CRED_I_out, &CRED_R_out, "../../uoscore-uedhoc/test_vectors/psks_r.txt");
		    
		    free(CRED_I_out.ptr);
			free(CRED_R_out.ptr);
			free(rPSK.ptr);
			free(rKID.ptr);
		    #endif

			edhoc_exporter(SHA_256, 4, &(data->PRK_exporter),&(data->msk));
			DEBUG_MSG("MSK");
			DEBUG_PRINT_ARRAY(data->msk.ptr, data->msk.len);
			edhoc_exporter(SHA_256, 5, &(data->PRK_exporter),&(data->emsk));
			DEBUG_MSG("EMSK");
			DEBUG_PRINT_ARRAY(data->emsk.ptr, data->emsk.len);
			edhoc_exporter(SHA_256, 6, &(data->PRK_exporter),&(data->method_id));
			DEBUG_MSG("Method-Id");
			DEBUG_PRINT_ARRAY(data->method_id.ptr, data->method_id.len);

			return;
		}

	}
	else {
		if (ROLE_SCHEME == 0){
			DEBUG_MSG("Protocol in Direct mode received a Role Reverse msg, abort.");
			return;
		}
		
		struct eap_edhoc_data_reverse *data = priv;
		
		if (data->state == MSG1_send) {
			// Finish sending MSG1 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish sending MSG1, we receive MSG2.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = MSG2_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);
		}

		if (data->state == MSG2_recv) {
			//Receiving MSG2.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG2 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish receiving MSG2, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;

			// Once we finish receiving MSG2, we generate and send MSG3.
			data->state = MSG3_send;

			fragment_buffer_free(&(data->frag_buffer));
			
			//Gen MSG3:
			enum err retval = msg3_gen(&(data->c_i), &(data->rc), &(data->cred_r_array), &(data->c_r), &(data->PRK_out));
			if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE_I;
				return; 
			}

			// Storing msg3 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			return;
		}
		if (data->state == MSG3_send) {

			// Finish sending MSG3 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				return;
			}

			// Once we finish sending MSG3, success + key derivation process.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = SUCCESS_I;
			
			DEBUG_MSG("EAP SUCCESS");

			prk_out2exporter(SHA_256, &(data->PRK_out), &(data->PRK_exporter));
			DEBUG_MSG("PRK_exporter");
			DEBUG_PRINT_ARRAY(data->PRK_exporter.ptr, data->PRK_exporter.len);
			
			#ifdef RESUMPTION
			struct byte_array rPSK;
			struct byte_array rKID;

			rPSK.ptr=malloc(16*sizeof(uint8_t));
			rPSK.len=16;

			rKID.ptr=malloc(1*sizeof(uint8_t));
			rKID.len=1;

			edhoc_exporter(SHA_256, rPSK_TAG, &(data->PRK_exporter),
						   &rPSK);
			DEBUG_MSG("rPSK:");
			DEBUG_PRINT_ARRAY(rPSK.ptr, rPSK.len);

			edhoc_exporter(SHA_256, rKID_TAG, &(data->PRK_exporter),
						   &rKID);
			DEBUG_MSG("rKID:");
			DEBUG_PRINT_ARRAY(rKID.ptr, rKID.len);

			//GENERATE CREDS FROM rPSK AND rKID.
			struct byte_array CRED_I_out;
			struct byte_array CRED_R_out;

			CRED_I_out.ptr=malloc(CRED_I_SIZE*sizeof(uint8_t));
			CRED_I_out.len=CRED_I_SIZE;

			CRED_R_out.ptr=malloc(CRED_R_SIZE*sizeof(uint8_t));
			CRED_R_out.len=CRED_R_SIZE;

			generate_CWT_cred("initiator", &rKID, &rPSK, &CRED_I_out);
			PRINT_ARRAY("CRED_I_out: ", CRED_I_out.ptr,
				    CRED_I_out.len);
			generate_CWT_cred("responder", &rKID, &rPSK, &CRED_R_out);
			PRINT_ARRAY("CRED_R_out: ", CRED_R_out.ptr,
				    CRED_R_out.len);

			//Storing RESUMPTION CREDS.
			//store_creds(&rKID, &CRED_I_out, &CRED_R_out, "../../uoscore-uedhoc/test_vectors/psks_i.txt");
		    
		    free(CRED_I_out.ptr);
			free(CRED_R_out.ptr);
			free(rPSK.ptr);
			free(rKID.ptr);
		    #endif

			edhoc_exporter(SHA_256, 4, &(data->PRK_exporter),&(data->msk));
			DEBUG_MSG("MSK");
			DEBUG_PRINT_ARRAY(data->msk.ptr, data->msk.len);
			edhoc_exporter(SHA_256, 5, &(data->PRK_exporter),&(data->emsk));
			DEBUG_MSG("EMSK");
			DEBUG_PRINT_ARRAY(data->emsk.ptr, data->emsk.len);
			edhoc_exporter(SHA_256, 6, &(data->PRK_exporter),&(data->method_id));
			DEBUG_MSG("Method-Id");
			DEBUG_PRINT_ARRAY(data->method_id.ptr, data->method_id.len);

			sm->EAP_state = EAP_SELECT_ACTION;
			sm->decision = DECISION_SUCCESS;

		}

		return;
	}
}

static u8 * eap_edhoc_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;
		u8 *key;

		if (data->state != SUCCESS)
			return NULL;

		key = os_memdup(data->msk.ptr, EAP_MSK_LEN);
		if (key == NULL)
			return NULL;
		*len = EAP_MSK_LEN;

		return key;
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;
		u8 *key;

		if (data->state != SUCCESS_I)
			return NULL;

		key = os_memdup(data->msk.ptr, EAP_MSK_LEN);
		if (key == NULL)
			return NULL;
		*len = EAP_MSK_LEN;

		return key;
	}
}

static u8 * eap_edhoc_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;
		u8 *key;

		if (data->state != SUCCESS)
			return NULL;
			
		key = os_memdup(data->emsk.ptr, EAP_EMSK_LEN);
		if (key == NULL)
			return NULL;
		*len = EAP_EMSK_LEN;
			
		return key;
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;
		u8 *key;

		if (data->state != SUCCESS_I)
			return NULL;
			
		key = os_memdup(data->emsk.ptr, EAP_EMSK_LEN);
		if (key == NULL)
			return NULL;
		*len = EAP_EMSK_LEN;
			
		return key;
	}
}

static u8 * eap_edhoc_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;

		if (data->state != SUCCESS)
			return NULL;
		
		*len = 1 + data->method_id.len;
		u8 *session_id = os_zalloc(*len);
		if (session_id == NULL)
			return NULL;
		
		session_id[0] = EAP_TYPE_EDHOC;

	    	// Copying method_id after the EAP_EDHOC type.
	    	os_memcpy(session_id + 1, data->method_id.ptr, data->method_id.len);

		return session_id;
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;

		if (data->state != SUCCESS_I)
			return NULL;
		
		*len = 1 + data->method_id.len;
		u8 *session_id = os_zalloc(*len);
		if (session_id == NULL)
			return NULL;
		
		session_id[0] = EAP_TYPE_EDHOC;

	    	// Copying method_id after the EAP_EDHOC type.
	    	os_memcpy(session_id + 1, data->method_id.ptr, data->method_id.len);

		return session_id;
	}
}

static bool eap_edhoc_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_edhoc_data *data = priv;
	return (data->state == SUCCESS || data->state == FAILURE);
}


static bool eap_edhoc_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_edhoc_data *data = priv;
	return data->state == SUCCESS;
}

int eap_server_edhoc_register(void)
{
	struct eap_method *eap;

	/* EAP types are defined in eap_common/eap_defs.h 
		CHECK THE NUMBER CHOSEN
	*/
	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_EDHOC, "EDHOC");
	if (eap == NULL)
		return -1;

	eap->init = eap_edhoc_init;
	eap->reset = eap_edhoc_reset;
	eap->buildReq = eap_edhoc_buildReq;
	eap->process = eap_edhoc_process;
	eap->isDone = eap_edhoc_isDone;
	eap->isSuccess = eap_edhoc_isSuccess;
	eap->getSessionId = eap_edhoc_get_session_id;
	eap->get_emsk = eap_edhoc_get_emsk;
	eap->getKey = eap_edhoc_getKey;

	return eap_server_method_register(eap);
}
