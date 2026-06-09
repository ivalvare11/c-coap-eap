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
#include <zephyr/net/coap.h>
#include <time.h>

#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "buffer_sizes.h"

// Config line to define the test vectors to use.
//"T1_RFC9529": Using RFC9529 test vectors.
//"ORIG": Using p256_v16 file test vectors.
#define ORIG
//#define T1_RFC9529

//#define MESSAGE4

#define URI_PATH 11

/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
static int start_coap_client(int *sockfd)
{
	struct sockaddr_in6 servaddr;
	// const char IPV6_SERVADDR[] = { "::1" };
	//const char IPV6_SERVADDR[] = { "2001:db8::2" };
	const char IPV6_SERVADDR[] = { "fd11:22::200" };
	int r = ipv6_sock_init(SOCK_CLIENT, IPV6_SERVADDR, &servaddr,
			       sizeof(servaddr), sockfd);
	if (r < 0) {
		printf("error during socket initialization (error code: %d)",
		       r);
		return -1;
	}
	return 0;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be send over the network. We use here CoAP as transport
 * @param	data pointer to the data that needs to be send
 */
enum err tx(void *sock, struct byte_array *data)
{
	/* Initialize the CoAP message */
	char *path = ".well-known/edhoc";
	struct coap_packet request;
	uint8_t _data[1000];

	struct timeval tv;
	struct tm *t_info;

	TRY_EXPECT(coap_packet_init(&request, _data, sizeof(_data), 1,
				    COAP_TYPE_CON, 8, coap_next_token(),
				    COAP_METHOD_POST, coap_next_id()),
		   0);

	/* Append options */
	TRY_EXPECT(coap_packet_append_option(&request, URI_PATH, path,
					     strlen(path)),
		   0);

	/* Append Payload marker if you are going to add payload */
	TRY_EXPECT(coap_packet_append_payload_marker(&request), 0);

	/* Append payload */
	TRY_EXPECT(coap_packet_append_payload(&request, data->ptr, data->len),
		   0);

	PRINT_ARRAY("CoAP packet", request.data, request.offset);
	gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
	t_info = localtime(&tv.tv_sec);
	printf("sent data timestamp:\n");
	printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
	       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);

	ssize_t n = send(*((int *)sock), request.data, request.offset, 0);
	if (n < 0) {
		printf("send failed with error code: %d\n", n);
	} else {
		printf("%d bytes sent\n", n);
	}

	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be received over the network. We use here CoAP as transport
 * @param	data pointer to the data that needs to be received
 */
enum err rx(void *sock, struct byte_array *data)
{
	int n;
	char buffer[MAXLINE];
	struct coap_packet reply;
	const uint8_t *edhoc_data_p;
	uint16_t edhoc_data_len;

	struct timeval tv;
	struct tm *t_info;

	/* receive */
	n = recv(*((int *)sock), (char *)buffer, MAXLINE, MSG_WAITALL);
	if (n < 0) {
		printf("recv error");
	}

	gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
	t_info = localtime(&tv.tv_sec);
	printf("received data timestamp:\n");
	printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
	       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);
	PRINT_ARRAY("received data", buffer, n);
	printf("received data byte %i\n", n);

	TRY_EXPECT(coap_packet_parse(&reply, buffer, n, NULL, 0), 0);

	edhoc_data_p = coap_packet_get_payload(&reply, &edhoc_data_len);

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

	int32_t s = 15;
	printf("Sleep for %d second after connection \n", s);
	k_sleep(K_SECONDS(s));

	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(rKID, 1, 1);
	BYTE_ARRAY_NEW(rPSK, 16, 16);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

#ifdef ORIG
	printk("TEST_VECTOR: %d\n", CONFIG_TEST_VECTOR);
	uint8_t TEST_VEC_NUM = CONFIG_TEST_VECTOR;
	// const uint8_t TEST_VEC_NUM = 7;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_i.sock = &sockfd;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	if (TEST_VEC_NUM > 6) {
		c_i.id_cred_psk.len = test_vectors[vec_num_i].id_cred_psk_len;
		c_i.id_cred_psk.ptr =
			(uint8_t *)test_vectors[vec_num_i].id_cred_psk;

		//c_i.cred_psk.len = test_vectors[vec_num_i].cred_psk_len;
		//c_i.cred_psk.ptr = (uint8_t *)test_vectors[vec_num_i].cred_psk;
	}

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;
#endif

#ifdef T1_RFC9529

	printf("TEST_VECTOR: RFC5929\n");
	c_i.sock = &sockfd;
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

#endif

	gettimeofday(&tv, NULL); // obtiene segundos + microsegundos
	t_info = localtime(&tv.tv_sec);
	printf("Init timestamp:\n");
	printf("timestamp: %02d:%02d:%02d.%03ld\n", t_info->tm_hour,
	       t_info->tm_min, t_info->tm_sec, tv.tv_usec / 1000);

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	start_coap_client(&sockfd);
	edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
			    ead_process);

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