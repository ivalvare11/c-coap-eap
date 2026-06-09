
#include "includes.h"

#include "common.h"
#include "eap_i.h"

#include "edhoc.h"
#include "edhoc_internal.h"
#include "./common/oscore_edhoc_error.h"
#include "../eap_common/eap_edhoc_common.h"
#include "psk_api.h"

#include <sys/time.h>

#ifdef MEASURE_TIME
struct timeval start, end;
double total_time_taken = 0.0;
#endif

struct eap_edhoc_data {

	struct byte_array PRK_exporter;
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array err_msg;
	
	enum { START, MSG1_send, MSG2_recv, MSG3_send, MSG4_recv, SUCCESS, FAILURE } state;
	struct byte_array c_r;
	struct edhoc_initiator_context c_i;
	struct cred_array cred_r_array;

	struct fragment_buffer_t frag_buffer;
	
	struct runtime_context rc;
};

struct eap_edhoc_data_reverse {

	struct byte_array PRK_exporter;
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array err_msg;
	
	enum { START_I, MSG1_recv, MSG2_send, MSG3_recv, SUCCESS_I, FAILURE_I } state;
	struct byte_array c_i;
	struct edhoc_responder_context c_r;
	struct cred_array cred_i_array;

	struct fragment_buffer_t frag_buffer;
	
	struct runtime_context rc;
};

#ifdef MEASURE_TIME
static void write_file(double result) {

    FILE *file = fopen("../../../tests/internal_times_peer.txt", "a");
    
    if (file == NULL) {
        return;
    }
    
    fprintf(file, "%f\n", result);
    
    fclose(file);
}
#endif

static void * data_init()
{
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
	data->c_r.ptr=os_zalloc(C_R_SIZE*sizeof(uint8_t));
	data->c_r.len=C_R_SIZE;

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

   	total_time_taken += time_taken;
    #endif

	return data;
}

static void * reverse_data_init()
{
	struct eap_edhoc_data_reverse *data;
	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = START_I;
	
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

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

   	total_time_taken += time_taken;
    #endif

	return data;
}

static void * eap_edhoc_init(struct eap_sm *sm)
{

	#ifdef MEASURE_TIME
	total_time_taken = 0.0;
	// Record the start time
    gettimeofday(&start, NULL);
    #endif

	if (ROLE_SCHEME == 0){
		return data_init();
	}
	else {
		return reverse_data_init();
	}
}


static void eap_edhoc_deinit(struct eap_sm *sm, void *priv)
{
	
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;
		os_free(data->PRK_exporter.ptr);
		os_free(data->msk.ptr);
		os_free(data->emsk.ptr);
		os_free(data->method_id.ptr);
		os_free(data->PRK_out.ptr);
		os_free(data->c_r.ptr);
		os_free(data->cred_r_array.ptr);
		os_free(data);
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;
		os_free(data->PRK_exporter.ptr);
		os_free(data->msk.ptr);
		os_free(data->emsk.ptr);
		os_free(data->method_id.ptr);
		os_free(data->PRK_out.ptr);
		os_free(data->c_i.ptr);
		os_free(data->cred_i_array.ptr);
		os_free(data);
	}
}

static struct wpabuf * send_empty(struct eap_method_ret *ret, const struct wpabuf *reqData, uint8_t flags)
{
	struct wpabuf *resp;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, 1, //len = 1 byte --> flags
				        EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL) {
		DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
		ret->ignore = true;
		return NULL;	
	}

	// Copy the content in the created response.
	wpabuf_put_u8(resp, flags);

	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = true;

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif
	
	return resp;
}

static struct wpabuf * send_msg(struct eap_method_ret *ret, const struct wpabuf *reqData, fragment_buffer_t *buffer, uint8_t flags)
{
	struct wpabuf *resp;

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

       	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, fragment_len + 1 + 4,
				             EAP_CODE_RESPONSE, eap_get_id(reqData));
		if (resp == NULL) {
			DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
			ret->ignore = true;
			return NULL;	
		}

		// Copy the content in the created response.
		wpabuf_put_u8(resp, flags);
		
		// Convert the length to network byte order
    	uint32_t network_order_len = htonl(buffer->len);

		wpabuf_put_le32(resp, network_order_len);
		wpabuf_put_data(resp, fragment, fragment_len);
	}
	else {
		if (retval == 1){ // Adding the M flags in all the fragments except the last one.
			flags |= EDHOC_M_FLAG;
		}

       	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, fragment_len + 1,
				             EAP_CODE_RESPONSE, eap_get_id(reqData));
		if (resp == NULL) {
			DEBUG_MSG("EAP-EDHOC: Failed to allocate response.");
			ret->ignore = true;
			return NULL;	
		}

		// Copy the content in the created response.
		wpabuf_put_u8(resp, flags);
		wpabuf_put_data(resp, fragment, fragment_len);
	}

	free(fragment);

	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = true;

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif

	return resp;
}

static struct wpabuf * eap_edhoc_process(struct eap_sm *sm, void *priv,
					struct eap_method_ret *ret,
					const struct wpabuf *reqData)
{

	#ifdef MEASURE_TIME
	// Record the start time
    gettimeofday(&start, NULL);
    #endif

	u8 flags_received = 0;
	u8 flags_send = 0;
	u32 msg_total_len = 0;

	const u8 *pos;
	size_t len;
		
	// Parsing the received EAP Request.
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_EDHOC, reqData, &len);
	if (pos == NULL || len == 0) {
		DEBUG_MSG("EAP-EDHOC: Invalid frame (pos=%p len=%lu)",
			   pos, (unsigned long) len);
		ret->ignore = true;
		return NULL;
	}	
		
	DEBUG_MSG("EAP-EDHOC: Received EDHOC Request.");
	
	// Parsing the flags octet.
	flags_received = *pos++;
	len--;

	DEBUG_MSG("EAP-EDHOC: Received flags: %u", flags_received);
	
	// Getting the msg Total Lenght value if present.
	if (flags_received & EDHOC_L_FLAG){
		if (len < 4){
			DEBUG_MSG("EAP-EDHOC: Invalid message: L flag activated but Length field not included.");
			return NULL;
		}

		memcpy(&msg_total_len, pos, 4);
		msg_total_len = ntohl(msg_total_len);  // Convert to host byte order if necessary
		pos+=4;
		len-=4;

		DEBUG_MSG("EAP-EDHOC: Received MSG Total Length: %u", msg_total_len);

	}
	else {
		msg_total_len = (u32)len;
	}
		
	// Process message received --> Direct schema, EAP Peer = Initiator:	
	if (!(flags_received & EDHOC_V_FLAG)) {
		
		if (ROLE_SCHEME == 1){
			DEBUG_MSG("Protocol in Role Reverse mode received a Direct mode msg, abort.");
			return NULL;
		}
		
		struct eap_edhoc_data *data = priv;	
		
		if (data->state == START){
			if (flags_received & EDHOC_S_FLAG) {	
			
				/*generate Initiator's credentials*/
				eap_edhoc_peer_cred_gen(&(data->cred_r_array), &(data->c_i));
				
				/*create message 1*/
				enum err retval = msg1_gen(&(data->c_i), &(data->rc));
				
				if (retval != ok){
					DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
					data->state = FAILURE;
					ret->ignore = true;
					return NULL; 
				}
				
				DEBUG_MSG("Gen MSG1:");
				DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);

				// Storing MSG1 in the fragmentation buffer to send it.
				fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
				memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

				data->state = MSG1_send;	
				
				//Preparing MSG1 to send:
				flags_send = 0;
		
				return send_msg(ret, reqData, &(data->frag_buffer), flags_send);	
   			}
   			else {
   				DEBUG_MSG("EAP-EDHOC: Invalid EDHOC-Start message: no S flag activated");
   				return NULL;
   			}
   		}

	    if (data->state == MSG1_send) {

	    	// Finish sending MSG1 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
			
				return send_msg(ret, reqData, &(data->frag_buffer), flags_send);
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
				flags_send = 0;
				return send_empty(ret, reqData, flags_send);
			}

			// Once we finish receiving MSG2, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return NULL;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;
			
			// Once we finish receiving MSG2, we generate and send MSG3.
			fragment_buffer_free(&(data->frag_buffer));

			data->state = MSG3_send;
			/*create message 3 (which process msg2 internally)*/
			enum err retval = msg3_gen(&(data->c_i), &(data->rc), &(data->cred_r_array), &(data->c_r), &(data->PRK_out));
			
			if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				ret->ignore = true;
				return NULL; 
			}
			
			DEBUG_MSG("Gen MSG3:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);
			DEBUG_MSG("");
			
			// Storing msg3 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			//Preparing MSG3 to send:
			flags_send = 0;
			
			return send_msg(ret, reqData, &(data->frag_buffer), flags_send);

		}

		if (data->state == MSG3_send) {

			// Finish sending MSG3 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
			
				return send_msg(ret, reqData, &(data->frag_buffer), flags_send);
			}

			// Once we finish sending MSG3, we receive MSG4.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = MSG4_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);

		}

		if (data->state == MSG4_recv) {

			//Receiving MSG4.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG4 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				return send_empty(ret, reqData, flags_send);
			}

			// Once we finish receiving MSG4, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return NULL;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;
			
			/*process message 4*/
			enum err retval = msg4_process(&(data->rc));
			
			if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				ret->ignore = true;
				return NULL; 
			}

			fragment_buffer_free(&(data->frag_buffer));
			
			// Key derivation process:
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
			
			data->state = SUCCESS;

	    	//Finally we send an empty EAP-EDHOC message to finish the protocol.
	    	flags_send = 0;
			struct wpabuf *resp = send_empty(ret, reqData, flags_send);
			
			#ifdef MEASURE_TIME
			//printf("TOTAL TIME TAKEN: %f\n", total_time_taken);
			write_file(total_time_taken);
			#endif

			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_COND_SUCC;
			ret->allowNotifications = true;

			return resp;
		}

		return NULL;
	}
	// Process message received --> Role Reverse schema, EAP Peer = Responder:	
	else {
                
		if (ROLE_SCHEME == 0){
			DEBUG_MSG("Protocol in Direct mode received a Role Reverse msg, abort.");
			return NULL;
		}
		
		struct eap_edhoc_data_reverse *data = priv;
		
		if (data->state == START_I){
			if (flags_received & EDHOC_S_FLAG) {

				data->state = MSG1_recv;			
				fragment_buffer_init(&(data->frag_buffer), msg_total_len);
			}
			else {
   				DEBUG_MSG("EAP-EDHOC: Invalid EDHOC-Start message: no S flag activated");
   				return NULL;
   			}
		}

		if (data->state == MSG1_recv){

			//Receiving MSG1.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG1 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= EDHOC_V_FLAG;
				return send_empty(ret, reqData, flags_send);
			}

			// Once we finish receiving MSG1, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return NULL;
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
				data->state = FAILURE_I;
				return NULL; 
			}
				
			DEBUG_MSG("Gen MSG2:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr, data->rc.msg.len);
			DEBUG_MSG("");
			
			// Storing MSG2 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			//Preparing MSG2 to send:
			flags_send = 0;
			//Activating the V flag to indicate Role-Rev.
			flags_send |= EDHOC_V_FLAG;
			
			return send_msg(ret, reqData, &(data->frag_buffer), flags_send);
		}

	    if (data->state == MSG2_send) {

			// Finish sending MSG2 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= EDHOC_V_FLAG;
			
				return send_msg(ret, reqData, &(data->frag_buffer), flags_send);
			}

			// Once we finish sending MSG2, we receive MSG3.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = MSG3_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);

		}

		if (data->state == MSG3_recv) {

			//Receiving MSG3.
			fragment_buffer_append_recv(&(data->frag_buffer), pos, len);

			// If more MSG3 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= EDHOC_V_FLAG;
				return send_empty(ret, reqData, flags_send);
			}

			// Once we finish receiving MSG3, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return NULL;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;

			/*process message 3*/
	    	enum err retval = msg3_process(&(data->c_r), &(data->rc), &(data->cred_i_array), &(data->PRK_out), &NULL_ARRAY);
	    	if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE_I;
				return NULL; 
			}

			fragment_buffer_free(&(data->frag_buffer));

			// Once we process MSG3, we accomplish the key derivation process.
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
			
			data->state = SUCCESS_I;

			flags_send = 0;
			//Activating the V flag to indicate Role-Rev.
			flags_send |= EDHOC_V_FLAG;
			struct wpabuf * finalACK =  send_empty(ret, reqData, flags_send); 
			
			#ifdef MEASURE_TIME
			//printf("TOTAL TIME TAKEN: %f\n", total_time_taken);
			write_file(total_time_taken);
			#endif

			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_COND_SUCC;
			ret->allowNotifications = true;

			return finalACK;
		}

		return NULL;
	}
}

static bool eap_edhoc_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	if (ROLE_SCHEME == 0){
		struct eap_edhoc_data *data = priv;
		return data->state == SUCCESS;
	}
	else {
		struct eap_edhoc_data_reverse *data = priv;
		return data->state == SUCCESS_I;
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

int eap_peer_edhoc_register(void)
{
	struct eap_method *eap;

	/* EAP types are defined in eap_common/eap_defs.h 
		CHECK THE NUMBER CHOSEN
	*/
	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_EDHOC, "EDHOC");
	if (eap == NULL)
		return -1;

	eap->init = eap_edhoc_init;
	eap->deinit = eap_edhoc_deinit;
	eap->process = eap_edhoc_process;
	eap->isKeyAvailable = eap_edhoc_isKeyAvailable;
	eap->getSessionId = eap_edhoc_get_session_id;
	eap->get_emsk = eap_edhoc_get_emsk;
	eap->getKey = eap_edhoc_getKey;

	return eap_peer_method_register(eap);
}
