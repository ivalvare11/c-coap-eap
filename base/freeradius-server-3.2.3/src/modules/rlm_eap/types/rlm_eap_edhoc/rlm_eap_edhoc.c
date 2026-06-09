/*
 * rlm_eap_edhoc.c    Handles that are called from eap
 *
 * Version:     $Id$
 *
 */
 
RCSID("$Id$") 
 
#include <stdio.h>
#include <stdlib.h>

#include "eap_edhoc.h"
#include <freeradius-devel/rad_assert.h> 

#include "edhoc_test_vectors_p256_v16.h"
#include "edhoc_test_vectors_rfc9529.h"

#include <sys/time.h>

#ifdef MEASURE_TIME
struct timeval start, end;
double total_time_taken = 0.0;
#endif

static void write_file(double result) {

    FILE *file = fopen("../../tests/internal_times_server.txt", "a");
    
    if (file == NULL) {
        return;
    }
    
    fprintf(file, "%f\n", result);
    
    fclose(file);
}

void fragment_buffer_init(fragment_buffer_t *buffer, size_t len) {
    buffer->data = malloc(len);
    buffer->len = len;
    buffer->offset = 0;
}

void fragment_buffer_free(fragment_buffer_t *buffer) {
    free(buffer->data);
}

// To fill the buffer during the receiving process.
void fragment_buffer_append_recv(fragment_buffer_t *buffer, const uint8_t *data, size_t len) {
    memcpy(buffer->data + buffer->offset, data, len);
    buffer->offset += len;
}

int more_fragments_needed(const fragment_buffer_t *buffer) {
    return buffer->offset < buffer->len;
}

int get_next_fragment(fragment_buffer_t *buffer, uint8_t *fragment, size_t *fragment_len) {
    if (buffer->offset >= buffer->len) {
        return 0;  // No more data to send
    }

    size_t remaining = buffer->len - buffer->offset;
    *fragment_len = remaining < MAX_FRAGMENT_SIZE ? remaining : MAX_FRAGMENT_SIZE;
    memcpy(fragment, buffer->data + buffer->offset, *fragment_len);
    buffer->offset += *fragment_len;
    
    // More data to send and this is the last fragment. In case this is the first and last fragment (total_msg < MTU), we also return this. 
    if (remaining == *fragment_len) return 2; 

	// More data to send and this is the first fragment.
    if (remaining == buffer->len) return 3; 

    return 1;  // More data to send.
}

/*
 *	Attach the EAP-EDHOC module --> init function.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	// "EAP EDHOC Instantiate"
	if (ROLE_SCHEME == 0){

		rlm_eap_edhoc_t		*data;
		*instance = data = talloc_zero(cs, rlm_eap_edhoc_t);
		if (!data) return -1;

		return 0;
	}
	else {
		rlm_eap_edhoc_t_rev		*data;
		*instance = data = talloc_zero(cs, rlm_eap_edhoc_t_rev);
		if (!data) return -1;

		return 0;
	}
}

void eap_edhoc_peer_cred_gen(struct cred_array *cred_r_array, struct edhoc_initiator_context *c_i){

	struct other_party_cred *cred_r;
	cred_r = (struct other_party_cred *)malloc(sizeof(struct other_party_cred));

#ifdef ORIG

	uint8_t vec_num_i = TEST_VECTORS_NUM - 1;

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

	//Reading creds from test vectors.
	if (TEST_VECTORS_NUM == 7){
		c_i->id_cred_psk.len = test_vectors[vec_num_i].id_cred_psk_len;
		c_i->id_cred_psk.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_psk;
	}
	//Reading creds from cred file. Deactivate if reading from tvs.
	/*if (TEST_VEC_NUM == 7){
		c_i->id_cred_psk.ptr = (uint8_t *)malloc(ID_CRED_PSK_SIZE);
		c_i->cred_i.ptr = (uint8_t *)malloc(CRED_I_SIZE);
		cred_r->cred.ptr = (uint8_t *)malloc(CRED_R_SIZE);

		if (get_last_creds(&(c_i->id_cred_psk), &(c_i->cred_i), &(cred_r->cred), "../uoscore-uedhoc/test_vectors/psks_i.txt")!=0)
			return;
	}*/

#endif

#ifdef T1_RFC9529

	c_i->c_i.len = T1_RFC9529__C_I_LEN;
	c_i->c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i->method = (enum method_type)T1_RFC9529__METHOD;
	c_i->suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i->suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i->ead_1.len = 0;
	c_i->ead_1.ptr = NULL;
	c_i->ead_3.len = 0;
	c_i->ead_3.ptr = NULL;
	c_i->id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i->id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i->cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i->cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i->g_x.len = T1_RFC9529__G_X_LEN;
	c_i->g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i->x.len = T1_RFC9529__X_LEN;
	c_i->x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i->g_i.len = 0;
	c_i->g_i.ptr = NULL;
	c_i->i.len = 0;
	c_i->i.ptr = NULL;
	c_i->sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i->sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i->pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i->pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;

	cred_r->id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r->id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r->cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r->cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r->g.len = 0;
	cred_r->g.ptr = NULL;
	cred_r->pk.len = T1_RFC9529__PK_R_LEN;
	cred_r->pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r->ca.len = 0;
	cred_r->ca.ptr = NULL;
	cred_r->ca_pk.len = 0;
	cred_r->ca_pk.ptr = NULL;
#endif

	cred_r_array->len = 1;
	cred_r_array->ptr = cred_r;
	
    uint32_t seed;
	struct byte_array X_random;
	X_random.ptr=malloc(32*sizeof(uint8_t));;
	X_random.len=32;
	struct byte_array G_X_random;
    G_X_random.ptr=malloc(32*sizeof(uint8_t));;
	G_X_random.len=32;
	
	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	
	if (seed_len == 0) {
	    DEBUG_MSG("Error: Unable to read random data from /dev/urandom");
	    return;
	}
	
	DEBUG_MSG("Seed");
	DEBUG_PRINT_ARRAY((uint8_t *)&seed, seed_len);
	//printf("X_random %d %d %d \n", P256, seed, X_random);
	/*create ephemeral DH keys from seed*/

	enum ecdh_alg alg = P256;

	#ifdef T1_RFC9529
		alg = X25519;
	#endif

	ephemeral_dh_key_gen(alg, seed, &X_random, &G_X_random);

	//printf("set prk_exporters %d %d %d\n", seed, seed_len,X_random.len);
    //exit(0);
	
	c_i->g_x.ptr = G_X_random.ptr;
	c_i->g_x.len = G_X_random.len;
	c_i->x.ptr = X_random.ptr;
	c_i->x.len = X_random.len;
	DEBUG_MSG("Public DH");
	DEBUG_PRINT_ARRAY(c_i->g_x.ptr, c_i->g_x.len);
	DEBUG_MSG("Private DH");
	DEBUG_PRINT_ARRAY(c_i->x.ptr, c_i->x.len);
	
	return;

}

void eap_edhoc_server_cred_gen(struct cred_array *cred_i_array, struct edhoc_responder_context *c_r){

	struct other_party_cred *cred_i;
	
	cred_i = (struct other_party_cred *)malloc(sizeof(struct other_party_cred));
	
#ifdef ORIG
	uint8_t vec_num_i = TEST_VECTORS_NUM - 1;

	c_r->c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r->c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r->suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r->suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r->ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r->ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r->ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r->ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r->id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r->id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r->cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r->cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r->g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r->g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r->y.len = test_vectors[vec_num_i].y_raw_len;
	c_r->y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r->g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r->g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r->r.len = test_vectors[vec_num_i].r_raw_len;
	c_r->r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r->sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r->sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r->pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r->pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	//Reading creds from tvs.
	if (TEST_VECTORS_NUM == 7){
		c_r->id_cred_psk.len = test_vectors[vec_num_i].id_cred_psk_len;
		c_r->id_cred_psk.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_psk;
	}
	//Reading creds from cred file. Deactivate if reading from tvs.
	/*if (TEST_VECTORS_NUM == 7){
		set_resp_creds_file("../uoscore-uedhoc/test_vectors/psks_r.txt");
	}*/
	
	cred_i->id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i->id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i->cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i->cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i->g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i->g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i->pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i->pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i->ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i->ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i->ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i->ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;
#endif
#ifdef T1_RFC9529

	c_r->c_r.ptr = (uint8_t *)T1_RFC9529__C_R;
	c_r->c_r.len = T1_RFC9529__C_R_LEN;
	c_r->suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r->suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;

	c_r->ead_2.ptr = NULL;
	c_r->ead_2.len = 0;
	c_r->ead_4.ptr = NULL;
	c_r->ead_4.len = 0;

	c_r->id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r->id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r->cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r->cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r->g_y.len = T1_RFC9529__G_Y_LEN;
	c_r->g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r->y.len = T1_RFC9529__Y_LEN;
	c_r->y.ptr = (uint8_t *)T1_RFC9529__Y;
	c_r->g_r.len = 0;
	c_r->g_r.ptr = NULL;
	c_r->r.len = 0;
	c_r->r.ptr = NULL;
	c_r->sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r->sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r->pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r->pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;

	cred_i->id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i->id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i->cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i->cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i->g.len = 0;
	cred_i->g.ptr = NULL;
	cred_i->pk.len = T1_RFC9529__PK_I_LEN;
	cred_i->pk.ptr = (uint8_t *)T1_RFC9529__PK_I;

	cred_i->ca.len = 0;
	cred_i->ca.ptr = NULL;
	cred_i->ca_pk.len = 0;
	cred_i->ca_pk.ptr = NULL;
#endif

	cred_i_array->len = 1;
	cred_i_array->ptr = cred_i;
	
	uint32_t seed;
	struct byte_array Y_random;
	Y_random.ptr=malloc(32*sizeof(uint8_t));;
	Y_random.len=32;
	struct byte_array G_Y_random;
    G_Y_random.ptr=malloc(32*sizeof(uint8_t));;
	G_Y_random.len=32;
	
	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	
	if (seed_len == 0) {
	    DEBUG_MSG("Error: Unable to read random data from /dev/urandom");
	    return;
	}
	
	DEBUG_MSG("Seed");
	DEBUG_PRINT_ARRAY((uint8_t *)&seed, seed_len);

	enum ecdh_alg alg = P256;

	#ifdef T1_RFC9529
		alg = X25519;
	#endif

	ephemeral_dh_key_gen(alg, seed, &Y_random, &G_Y_random);
	
	c_r->g_y.ptr = G_Y_random.ptr;
	c_r->g_y.len = G_Y_random.len;
	c_r->y.ptr = Y_random.ptr;
	c_r->y.len = Y_random.len;
	DEBUG_MSG("Public DH");
	DEBUG_PRINT_ARRAY(c_r->g_y.ptr, c_r->g_y.len);
	DEBUG_MSG("Private DH");
	DEBUG_PRINT_ARRAY(c_r->y.ptr, c_r->y.len);
	
	return;
}

static int send_msg(eap_handler_t *handler, fragment_buffer_t *buffer, uint8_t flags)
{
	
	handler->eap_ds->request->code = PW_EAP_REQUEST; 
	handler->eap_ds->request->type.num = PW_EAP_EDHOC; // EAP-EDHOC ID
	
    uint8_t *fragment = (uint8_t *)malloc(MAX_FRAGMENT_SIZE);
    size_t fragment_len;
	
	int retval = get_next_fragment(buffer, fragment, &fragment_len);
	
	if (retval == 0){
		free(fragment);
		return 0;
	} 
	
	if (retval == 3){ // First fragment of the message. Adding the Length header.
		handler->eap_ds->request->type.data = talloc_array(handler->eap_ds->request, uint8_t, fragment_len + 1 + 4); //+1 for the flags byte, +4 for the Length header.
		handler->eap_ds->request->type.length = fragment_len + 1 + 4;
		flags |= PW_EDHOC_L_FLAG;
		flags |= PW_EDHOC_M_FLAG; 
		handler->eap_ds->request->type.data[0] = flags;
		
		// Convert the length to network byte order
    	uint32_t network_order_len = htonl(buffer->len);
       	
       	memcpy(handler->eap_ds->request->type.data + 1, &(network_order_len), sizeof(buffer->len));
       	memcpy(handler->eap_ds->request->type.data + 5, fragment , fragment_len);
	}
	else {
		handler->eap_ds->request->type.data = talloc_array(handler->eap_ds->request, uint8_t, fragment_len + 1); //+1 for the flags byte.
		handler->eap_ds->request->type.length = fragment_len + 1;
		if (retval == 1){ // Adding the M flags in all the fragments except the last one.
			flags |= PW_EDHOC_M_FLAG;
		}
		handler->eap_ds->request->type.data[0] = flags;
       	memcpy(handler->eap_ds->request->type.data + 1, fragment , fragment_len);
	}

	free(fragment);

	handler->stage = PROCESS;

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif

	return 1;
}

static int send_empty(eap_handler_t *handler, uint8_t flags)
{
	
	handler->eap_ds->request->code = PW_EAP_REQUEST; 
	handler->eap_ds->request->type.num = PW_EAP_EDHOC; // EAP-EDHOC ID
	handler->eap_ds->request->type.data = talloc_array(handler->eap_ds->request, uint8_t, 1); //1 for the flags byte.
	handler->eap_ds->request->type.length = 1;
	handler->eap_ds->request->type.data[0] = flags;
	
	handler->stage = PROCESS;

    #ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif

	return 1;
}

/*
 *	Initiate the EAP-EDHOC session --> start function.
 */
static int mod_session_init_edhoc(void *type_arg, eap_handler_t *handler)
{

	DEBUG_MSG("\n_____________ mod_session_init_edhoc");

    #ifdef MEASURE_TIME
	total_time_taken = 0.0;
	// Record the start time
    gettimeofday(&start, NULL);
    #endif
	
	if (ROLE_SCHEME == 0){
	
		rlm_eap_edhoc_t *data;
		data = type_arg;
		
		data->state = START;

		data->PRK_exporter.ptr=malloc(32*sizeof(uint8_t));
		data->PRK_exporter.len=32;	

		data->msk.ptr=malloc(64*sizeof(uint8_t));
		data->msk.len=64;
	  
	    data->emsk.ptr=malloc(64*sizeof(uint8_t));
		data->emsk.len=64;
		
		data->method_id.ptr=malloc(64*sizeof(uint8_t));
		data->method_id.len=64;

		data->PRK_out.ptr=malloc(32*sizeof(uint8_t));
	    data->PRK_out.len=32;
	    	
	    data->err_msg.ptr = NULL;
	    data->err_msg.len = 0;

		runtime_context_init(&(data->rc));
		
		data->c_i.ptr=malloc(C_I_SIZE*sizeof(uint8_t));
		data->c_i.len=C_I_SIZE;
		
		//fragment_buffer_init(&data->frag_buffer, 0);
		
		//Sending EDHOC Start msg.
		
		uint8_t flags = 0;
		//Activating the S flag in the Start message.
		flags |= PW_EDHOC_S_FLAG;

		return send_empty(handler, flags);
	}
	else {
		rlm_eap_edhoc_t_rev *data;
		data = type_arg;
		
		data->state = MSG1_send;
		
		data->PRK_exporter.ptr=malloc(32*sizeof(uint8_t));
		data->PRK_exporter.len=32;	

		data->msk.ptr=malloc(64*sizeof(uint8_t));
		data->msk.len=64;
	  
	    data->emsk.ptr=malloc(64*sizeof(uint8_t));
		data->emsk.len=64;
		
		data->method_id.ptr=malloc(64*sizeof(uint8_t));
		data->method_id.len=64;

		data->PRK_out.ptr=malloc(32*sizeof(uint8_t));
	    data->PRK_out.len=32;
	    	
	    data->err_msg.ptr = NULL;
	    data->err_msg.len = 0;

		runtime_context_init(&(data->rc));
		
		data->c_r.ptr=malloc(C_R_SIZE*sizeof(uint8_t));
		data->c_r.len=C_R_SIZE;
		
		//the initiator generates its credentials before generating msg1.
		eap_edhoc_peer_cred_gen(&(data->cred_r_array), &(data->c_i));
		
		//Gen MSG1:
		enum err retval = msg1_gen(&(data->c_i), &(data->rc));
		if (retval != ok){
	        	DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
        		data->state = FAILURE_I;
        		return -1; 
		}
		
		DEBUG_MSG("MSG1 generated:");
		DEBUG_PRINT_ARRAY(data->rc.msg.ptr,data->rc.msg.len);
		DEBUG_MSG("");
		
		// Storing msg1 in the fragmentation buffer to send it.
		fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
		memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

		//Preparing MSG1 to send:
		uint8_t flags = 0;
		//Activating the S flag in the MSG1 when Role-Rev.
		flags |= PW_EDHOC_S_FLAG;
		//Activating the V flag to indicate Role-Rev.
		flags |= PW_EDHOC_V_FLAG;
		
		return send_msg(handler, &(data->frag_buffer), flags);
	}
	
}

/*
 *	Process next round of EAP method --> step function.
 */
static int mod_process_edhoc(void *type_arg, eap_handler_t *handler)
{

	DEBUG_MSG("\n_____________ mod_process_edhoc ()");
	
	DEBUG_MSG("Received from EAP peer.");
	DEBUG_MSG(": ");
	DEBUG_MSG("ID:  %d",handler->eap_ds->response->id);
	DEBUG_MSG("length:  %ld",handler->eap_ds->response->length);
	DEBUG_MSG("type.num:  %d",handler->eap_ds->response->type.num);
	DEBUG_MSG("type.length:  %ld",handler->eap_ds->response->type.length);
	
	#ifdef MEASURE_TIME
	// Record the start time
    gettimeofday(&start, NULL);
    #endif

	uint8_t flags_received = 0;
	uint8_t flags_send = 0;
	size_t msg_total_len = 0;
	
	if (handler->eap_ds->response->type.length < 1) {
		DEBUG_MSG("EAP-EDHOC: Invalid message: no Flags octet included");
		return -1;
	} else {
		flags_received = handler->eap_ds->response->type.data[0];
		DEBUG_MSG("type.flags:  %d\n",flags_received);
		handler->eap_ds->response->type.data += 1;
		handler->eap_ds->response->type.length -= 1;

	}
	
	if (flags_received & PW_EDHOC_L_FLAG){

		if (handler->eap_ds->response->type.length < 4){
			DEBUG_MSG("EAP-EDHOC: Invalid message: L flag activated but Length field not included.");
			return -1;
		}
		
		memcpy(&msg_total_len, handler->eap_ds->response->type.data, 4);

		msg_total_len = ntohl(msg_total_len);  // Convert to host byte order if necessary

		DEBUG_MSG("type.msg_TotalLength: %ld", msg_total_len);

		handler->eap_ds->response->type.data += 4;
		handler->eap_ds->response->type.length -= 4;
		
		DEBUG_MSG("type.data:");
		DEBUG_PRINT_ARRAY(handler->eap_ds->response->type.data, handler->eap_ds->response->type.length);

	}
	else {
		if (handler->eap_ds->response->type.length > 0){
			DEBUG_MSG("type.data:");
			DEBUG_PRINT_ARRAY(handler->eap_ds->response->type.data, handler->eap_ds->response->type.length);
			msg_total_len = handler->eap_ds->response->type.length;
		}
		else {
			DEBUG_MSG("type.data: Empty\n");
		}

	}
	
	if (!(flags_received & PW_EDHOC_V_FLAG)) {
	
		if (ROLE_SCHEME == 1){
			DEBUG_MSG("EAP-EDHOC: Protocol in Role Reverse mode received a Direct mode msg, abort.");
			return -1;
		}
		
		rlm_eap_edhoc_t *data = type_arg;
		if (data->state == START){

			data->state = MSG1_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);
		}

		if (data->state == MSG1_recv){

			//Receiving MSG1.
			fragment_buffer_append_recv(&(data->frag_buffer), handler->eap_ds->response->type.data, handler->eap_ds->response->type.length);
			
			// If more MSG1 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				return send_empty(handler, flags_send);
			}

			// Once we finish receiving MSG1, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return -1;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;

			//After receiving MSG1, the responder generates its credentials.
			eap_edhoc_server_cred_gen(&(data->cred_i_array), &(data->c_r));
			
			// Once we finish receiving MSG1, we generate and send MSG2.
			data->state = MSG2_send;

			fragment_buffer_free(&(data->frag_buffer));
			
			//Gen MSG2:
			enum err retval = msg2_gen(&(data->c_r), &(data->rc), &(data->c_i));
			if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				return -1; 
			}
			
			DEBUG_MSG("MSG2 generated:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr,data->rc.msg.len);
			DEBUG_MSG("");

			// Storing MSG2 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			//Preparing MSG2 to send:
			flags_send = 0;
			
			return send_msg(handler, &(data->frag_buffer), flags_send);
		}
			
		if (data->state == MSG2_send){

			// Finish sending MSG2 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
			
				return send_msg(handler, &(data->frag_buffer), flags_send);
			}

			// Once we finish sending MSG2, we receive MSG3.
			fragment_buffer_free(&(data->frag_buffer));
			
			data->state = MSG3_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);
		}

		if (data->state == MSG3_recv){
			//Receiving MSG3.
			fragment_buffer_append_recv(&(data->frag_buffer), handler->eap_ds->response->type.data, handler->eap_ds->response->type.length);
			
			// If more MSG3 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				return send_empty(handler, flags_send);
			}

			// Once we finish receiving MSG3, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return -1;
			}
			
			memcpy(data->rc.msg.ptr, data->frag_buffer.data, data->frag_buffer.len);
			data->rc.msg.len = data->frag_buffer.len;

			//Processing MSG3:

			enum err retval = msg3_process(&(data->c_r), &(data->rc), &(data->cred_i_array), &(data->PRK_out), &NULL_ARRAY);
	    		if (retval != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval);
				data->state = FAILURE;
				return -1; 
			}
			
			// If MSG3 is processed successfully, we generate and send MSG4.
			data->state = MSG4_send;

			fragment_buffer_free(&(data->frag_buffer));
			
			//Gen MSG4:
			
			enum err retval2 = msg4_gen(&(data->c_r), &(data->rc));
			if (retval2 != ok){
				DEBUG_MSG("EAP-EDHOC: uEDHOC error %d.", retval2);
				data->state = FAILURE;
				return -1; 
			}
			
			DEBUG_MSG("MSG4 generated:");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr,data->rc.msg.len);
			DEBUG_MSG("");

			// Storing MSG4 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			//Preparing MSG4 to send:
			flags_send = 0;
			
			return send_msg(handler, &(data->frag_buffer), flags_send);
		}

		if (data->state == MSG4_send){

			// Finish sending MSG4 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
			
				return send_msg(handler, &(data->frag_buffer), flags_send);
			}

			fragment_buffer_free(&(data->frag_buffer));

			// Once we finish sending MSG4, we accomplish the key derivation process.
			DEBUG_MSG("EAP SUCCESS");

			// Key derivation process:
			prk_out2exporter(SHA_256, &(data->PRK_out), &(data->PRK_exporter));
			DEBUG_MSG("PRK_exporter: ");
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
			//store_creds(&rKID, &CRED_I_out, &CRED_R_out, "../uoscore-uedhoc/test_vectors/psks_r.txt");
		    
		    free(CRED_I_out.ptr);
			free(CRED_R_out.ptr);
			free(rPSK.ptr);
			free(rKID.ptr);
		    #endif

			edhoc_exporter(SHA_256, 4, &(data->PRK_exporter),&(data->msk));
			DEBUG_MSG("MSK: ");
			DEBUG_PRINT_ARRAY(data->msk.ptr, data->msk.len);
			edhoc_exporter(SHA_256, 5, &(data->PRK_exporter),&(data->emsk));
			DEBUG_MSG("EMSK: ");
			DEBUG_PRINT_ARRAY(data->emsk.ptr, data->emsk.len);
			edhoc_exporter(SHA_256, 6, &(data->PRK_exporter),&(data->method_id));
			DEBUG_MSG("Method-Id: ");
			DEBUG_PRINT_ARRAY(data->method_id.ptr, data->method_id.len);
			
			data->state = SUCCESS;
			
			handler->eap_ds->request->code = PW_EAP_SUCCESS;
			
			/*
			 * return the MSK
			 */
			uint8_t msk[64]={0};
			memcpy(msk,data->msk.ptr, data->msk.len);

			eap_add_reply(handler->request, "MS-MPPE-Recv-Key", msk, 32);
			eap_add_reply(handler->request, "MS-MPPE-Send-Key", msk+32, 32);
		}	
	}
	else {
		if (ROLE_SCHEME == 0){
			DEBUG_MSG("EAP-EDHOC: Protocol in Direct mode received a Role Reverse msg, abort.");
			return -1;
		}

		rlm_eap_edhoc_t_rev *data = type_arg;
	
		if (data->state == MSG1_send){

			// Finish sending MSG1 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= PW_EDHOC_V_FLAG;
			
				return send_msg(handler, &(data->frag_buffer), flags_send);
			}

			// Once we finish sending MSG1, we receive MSG2.
			fragment_buffer_free(&(data->frag_buffer));

			data->state = MSG2_recv;			
			fragment_buffer_init(&(data->frag_buffer), msg_total_len);
		}
		
		if (data->state == MSG2_recv){
			//Receiving MSG2.
			fragment_buffer_append_recv(&(data->frag_buffer), handler->eap_ds->response->type.data, handler->eap_ds->response->type.length);

			// If more MSG2 fragments are needed, send empty msg.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= PW_EDHOC_V_FLAG;
				return send_empty(handler, flags_send);
			}

			// Once we finish receiving MSG2, we copy it into uedhoc structures.

			if (data->frag_buffer.len > sizeof(data->rc.msg_buf)){
				DEBUG_MSG("insufficient space in buffer");
				return -1;
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
				return -1; 
			}
			
			DEBUG_MSG("MSG3 generated: ");
			DEBUG_PRINT_ARRAY(data->rc.msg.ptr,data->rc.msg.len);
			DEBUG_MSG("");

			// Storing msg3 in the fragmentation buffer to send it.
			fragment_buffer_init(&(data->frag_buffer), data->rc.msg.len);
			memcpy(data->frag_buffer.data, data->rc.msg.ptr, data->rc.msg.len);

			//Preparing MSG3 to send:
			flags_send = 0;
			//Activating the V flag to indicate Role-Rev.
			flags_send |= PW_EDHOC_V_FLAG;
			
			return send_msg(handler, &(data->frag_buffer), flags_send);
		}

		if (data->state == MSG3_send){

			// Finish sending MSG3 if fragmentation.
			if (more_fragments_needed(&(data->frag_buffer))){
				flags_send = 0;
				//Activating the V flag to indicate Role-Rev.
				flags_send |= PW_EDHOC_V_FLAG;
			
				return send_msg(handler, &(data->frag_buffer), flags_send);
			}

			// Once we finish sending MSG3, we receive MSG4.
			fragment_buffer_free(&(data->frag_buffer));
			
			//If MSG3 is correctly sent, we enter in SUCCESS_I state.
			data->state = SUCCESS_I;
			
			DEBUG_MSG("EAP SUCCESS");


			// Key derivation process:
			prk_out2exporter(SHA_256, &(data->PRK_out), &(data->PRK_exporter));
			DEBUG_MSG("PRK_exporter: ");
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
			//store_creds(&rKID, &CRED_I_out, &CRED_R_out, "../uoscore-uedhoc/test_vectors/psks_i.txt");
		    
		    free(CRED_I_out.ptr);
			free(CRED_R_out.ptr);
			free(rPSK.ptr);
			free(rKID.ptr);
		    #endif

			edhoc_exporter(SHA_256, 4, &(data->PRK_exporter),&(data->msk));
			DEBUG_MSG("MSK: ");
			DEBUG_PRINT_ARRAY(data->msk.ptr, data->msk.len);
			edhoc_exporter(SHA_256, 5, &(data->PRK_exporter),&(data->emsk));
			DEBUG_MSG("EMSK: ");
			DEBUG_PRINT_ARRAY(data->emsk.ptr, data->emsk.len);
			edhoc_exporter(SHA_256, 6, &(data->PRK_exporter),&(data->method_id));
			DEBUG_MSG("Method-Id: ");
			DEBUG_PRINT_ARRAY(data->method_id.ptr, data->method_id.len);
			
			handler->eap_ds->request->code = PW_EAP_SUCCESS;
			
			/*
			 * return the MSK
			 */
			uint8_t msk[64]={0};
			memcpy(msk,data->msk.ptr, data->msk.len);

			eap_add_reply(handler->request, "MS-MPPE-Recv-Key", msk, 32);
			eap_add_reply(handler->request, "MS-MPPE-Send-Key", msk+32, 32);
		}
	}

	#ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

   	total_time_taken += time_taken;

   	//printf("TOTAL TIME TAKEN: %f\n", total_time_taken);
	write_file(total_time_taken);

    #endif

	return 1;

}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_edhoc;
rlm_eap_module_t rlm_eap_edhoc = {
	.name		= "eap_edhoc",
	.instantiate	= mod_instantiate,		/* Create new submodule instance */
	.session_init	= mod_session_init_edhoc,	/* Initialise a new EAP session */
	.process	= mod_process_edhoc		/* Process next round of EAP method */
};
