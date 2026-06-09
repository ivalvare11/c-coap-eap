#include "includes.h"

#include "common.h"
#include "edhoc.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "psk_api.h"

#include "eap_edhoc_common.h"


void eap_edhoc_peer_cred_gen(struct cred_array *cred_r_array, struct edhoc_initiator_context *c_i){

	struct other_party_cred *cred_r;
	cred_r = (struct other_party_cred *)os_zalloc(sizeof(struct other_party_cred));

	
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
		c_i->id_cred_i.len = test_vectors[vec_num_i].id_cred_r_len;
		c_i->id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	}
	//Reading creds from cred file. Deactivate if reading from tvs.
	/*if (TEST_VECTORS_NUM == 7){
		c_i->id_cred_psk.ptr = (uint8_t *)malloc(ID_CRED_PSK_SIZE);
		c_i->cred_i.ptr = (uint8_t *)malloc(CRED_I_SIZE);
		cred_r->cred.ptr = (uint8_t *)malloc(CRED_R_SIZE);

		if (get_last_creds(&(c_i->id_cred_psk), &(c_i->cred_i), &(cred_r->cred), "../../uoscore-uedhoc/test_vectors/psks_i.txt")!=0)
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
	X_random.ptr=os_zalloc(32*sizeof(uint8_t));;
	X_random.len=32;
	struct byte_array G_X_random;
    G_X_random.ptr=os_zalloc(32*sizeof(uint8_t));;
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
	cred_i = (struct other_party_cred *)os_zalloc(sizeof(struct other_party_cred));

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
		c_r->id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
		c_r->id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	}
	//Reading creds from cred file. Deactivate if reading from tvs.
	/*if (TEST_VECTORS_NUM == 7){
		set_resp_creds_file("../../uoscore-uedhoc/test_vectors/psks_r.txt");
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
	Y_random.ptr=os_zalloc(32*sizeof(uint8_t));;
	Y_random.len=32;
	struct byte_array G_Y_random;
    	G_Y_random.ptr=os_zalloc(32*sizeof(uint8_t));;
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

