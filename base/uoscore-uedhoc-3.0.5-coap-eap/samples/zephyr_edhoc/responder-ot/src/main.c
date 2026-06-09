/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <stdio.h>

#include <zephyr/net/coap.h>

#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "edhoc_test_vectors_rfc9529.h"

// Config line to define the test vectors to use.
//"T1_RFC9529": Using RFC9529 test vectors.
//"ORIG": Using p256_v16 file test vectors.
#define ORIG
//#define T1_RFC9529

//#define MESSAGE4

struct sockaddr_storage client_addr;
socklen_t client_addr_len;

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(int *sockfd)
{
	int err;

	struct sockaddr_in6 servaddr;
	//struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	//const char IPV6_SERVADDR[] = { "2001:db8::1" };
	const char IPV6_SERVADDR[] = { "fd11:22::200" };
	err = ipv6_sock_init(SOCK_SERVER, IPV6_SERVADDR, &servaddr,
			     sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}

	return 0;
}

struct coap_packet cp_req;

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
	char buffer[MAXLINE];
	struct coap_packet cp_ack;
	int r;
	const uint8_t COAP_CHANGED = 0b01000100;

	struct timeval tv;
	struct tm *t_info;

	r = coap_ack_init(&cp_ack, &cp_req, buffer, sizeof(buffer),
			  COAP_CHANGED);
	if (r < 0) {
		printf("coap_ack_init failed\n");
		return unexpected_result_from_ext_lib;
	}

	r = coap_packet_append_payload_marker(&cp_ack);
	if (r < 0) {
		printf("coap_packet_append_payload_marker failed\n");
		return unexpected_result_from_ext_lib;
	}

	r = coap_packet_append_payload(&cp_ack, data->ptr, data->len);
	if (r < 0) {
		printf("coap_packet_append_payload failed\n");
		return unexpected_result_from_ext_lib;
	}

	gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
	t_info = localtime(&tv.tv_sec);
	printf("sent data timestamp:\n");
	printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
	       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);
	PRINT_ARRAY("Sending CoAP message", buffer, cp_ack.offset);

	r = sendto(*((int *)sock), buffer, cp_ack.offset, 0,
		   (struct sockaddr *)&client_addr, client_addr_len);
	if (r < 0) {
		printf("Error: failed to send reply (Code: %d, ErrNo: %d)\n", r,
		       errno);
		return r;
	}

	printf("Sending message bytes: %i\n", r);
	return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
	int n;
	char buffer[MAXLINE];

	struct timeval tv;
	struct tm *t_info;

	const uint8_t *edhoc_data_p;
	uint16_t edhoc_data_len;

	/* receive */
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	memset(&cp_req, 0, sizeof(cp_req));
	memset(&buffer, 0, sizeof(buffer));

	printf("waiting to receive in rx()\n");
	n = recvfrom(*((int *)sock), (char *)buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&client_addr, &client_addr_len);
	if (n < 0) {
		printf("recv error\n");
	}

	gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
	t_info = localtime(&tv.tv_sec);
	printf("received data timestamp:\n");
	printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
	       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);

	printf("received data message bytes: %i\n", n);
	PRINT_ARRAY("received data", buffer, n);

	TRY_EXPECT(coap_packet_parse(&cp_req, buffer, n, NULL, 0), 0);

	edhoc_data_p = coap_packet_get_payload(&cp_req, &edhoc_data_len);

	PRINT_ARRAY("received EDHOC data", edhoc_data_p, edhoc_data_len);

	if (data->len >= edhoc_data_len) {
		memcpy(data->ptr, edhoc_data_p, edhoc_data_len);
		data->len = edhoc_data_len;
	} else {
		printf("insufficient space in buffer");
		return buffer_to_small;
	}

	return ok;
}

int internal_main(void)
{
	struct timeval tv;
	struct tm *t_info;

	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);

	BYTE_ARRAY_NEW(rKID, 1, 1);
	BYTE_ARRAY_NEW(rPSK, 16, 16);

	BYTE_ARRAY_NEW(err_msg, 0, 0);

	int32_t s = 15;
	printf("Sleep for %d second after connection \n", s);
	k_sleep(K_SECONDS(s));

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	start_coap_server(&sockfd);

#ifdef ORIG

	//uint8_t TEST_VEC_NUM = 7;
	printk("TEST_VECTOR: %d\n", CONFIG_TEST_VECTOR);
	uint8_t TEST_VEC_NUM = CONFIG_TEST_VECTOR;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_r.sock = &sockfd;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	//set_resp_psk_file("../../../test_vectors/psks_r.txt");

	if (TEST_VEC_NUM > 6) {
		c_r.id_cred_psk.len = test_vectors[vec_num_i].id_cred_psk_len;
		c_r.id_cred_psk.ptr =
			(uint8_t *)test_vectors[vec_num_i].id_cred_psk;

		//c_r.cred_psk.len = test_vectors[vec_num_i].cred_psk_len;
		//c_r.cred_psk.ptr = (uint8_t *)test_vectors[vec_num_i].cred_psk;
	}

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;
#endif

#ifdef T1_RFC9529

	printf("TEST_VECTOR: RFC5929\n");

	c_r.sock = &sockfd;
	c_r.c_r.len = T1_RFC9529__C_R_LEN;
	c_r.c_r.ptr = (uint8_t *)T1_RFC9529__C_R;
	c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r.g_y.len = T1_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r.y.len = T1_RFC9529__Y_LEN;
	c_r.y.ptr = (uint8_t *)T1_RFC9529__Y;
	c_r.g_r.len = 0;
	c_r.g_r.ptr = NULL;
	c_r.r.len = 0;
	c_r.r.ptr = NULL;
	c_r.sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r.sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r.pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r.pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;

	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.g.len = 0;
	cred_i.g.ptr = NULL;
	cred_i.pk.len = T1_RFC9529__PK_I_LEN;
	cred_i.pk.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;
#endif

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	while (1) {
		edhoc_responder_run(&c_r, &cred_i_array, &err_msg, &PRK_out, tx,
				    rx, ead_process);
		PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

		prk_out2exporter(SHA_256, &PRK_out, &prk_exporter);
		PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

		//RESUMPTION DERIVATION.
		TRY(edhoc_exporter(SHA_256, rPSK_TAG, &prk_exporter,
					   &rPSK));
		PRINT_ARRAY("rPSK: ", rPSK.ptr,
				    rPSK.len);

		TRY(edhoc_exporter(SHA_256, rKID_TAG, &prk_exporter,
					   &rKID));
		PRINT_ARRAY("rKID: ", rKID.ptr,
				    rKID.len);

		// OSCORE KEY DERIVATION.
		edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			       &oscore_master_secret);
		PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
			    oscore_master_secret.len);

		edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			       &oscore_master_salt);
		PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
			    oscore_master_salt.len);

		gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
		t_info = localtime(&tv.tv_sec);
		printf("Finish timestamp:\n");
		printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
		       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);
	}

	close(sockfd);
	return 0;
}

void main(void)
{
	int r = internal_main();
	if (r != 0) {
		printf("error during initiator run. Error code: %d\n", r);
	}
}