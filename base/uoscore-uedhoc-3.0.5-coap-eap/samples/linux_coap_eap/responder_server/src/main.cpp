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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C"
{
	#include "eap_methods.h"
	#include "eap-peer.h"
	#include "oscore.h"
	#include "oscore_context.h"
	#include "sock.h"
}

#include "cantcoap.h"
#include "coap_transport.h"

#define RID_I 40

#define BUFFER_CHAR_SIZE 16

#define CONNECTION_ERROR -1

#define PEER_ADDRESS "127.0.0.1"
#define AUTHENTICATOR_ADDRESS "127.0.0.2"
#define AUTHENTICATOR_PORT 5682
#define PEER_PORT 5683

#define USE_IPV4

SocketAddress sockaddr_auth;
SocketAddress sockaddr_peer;

static char well_known_uri[] = ".well-known/coap-eap";

static char current_uri[BUFFER_CHAR_SIZE * 2] = "/a/eap/1";
static int uri_counter = 1;

static uint8_t rid_c = 0;
static uint16_t last_mid = 0;
static uint32_t last_token = 0;

/**
 * @brief	Sends message number 0 of the flow, that is, the initial POST
 * @param	sock	File descriptor of the socket used for sending the request
 * @retval	Generic connection error if failure
 */
static void send_initial_CoAP_request(int sock)
{
	struct byte_array payload;
	payload.ptr = (uint8_t *)current_uri;
	payload.len = strlen(current_uri);

	last_mid++;
	last_token++;

    uint16_t mid = last_mid;
    uint32_t token = last_token;

    CoapPDU *pdu = new CoapPDU();
    pdu->reset();
    pdu->setVersion(1);
    pdu->setType(CoapPDU::COAP_NON_CONFIRMABLE);
    pdu->setCode(CoapPDU::COAP_POST);
    pdu->setToken((uint8_t *)&token, sizeof(token));
    pdu->setMessageID(mid++);
    pdu->setURI(well_known_uri, strlen(well_known_uri));

	// * No successful responses allowed (new Option added to cantcoap.h and cantcoap.cpp)
	uint8_t no_response = 2;
	pdu->addOption(CoapPDU::COAP_OPTION_NO_RESPONSE, sizeof(no_response), &no_response);

    pdu->setPayload(payload.ptr, payload.len);

	configure_sock_addr(&sockaddr_auth, AUTHENTICATOR_ADDRESS, PEER_PORT);

	tx(sock, pdu, &sockaddr_auth, "Authenticator");
}

/**
 * @brief	In the first exchange of the flow, the Peer stores the RID-C from the Authenticator
 * @param	i		Number of the iteration (should be equal to 0, that is, when the Peer receives the EAP Request/Identity)
 * @param	payload	The payload of the CoAP message that encapsulates the EAP Request/Identity
 */
void store_rid_c(int i, struct byte_array *payload)
{
	if (i == 0 && payload->len > sizeof(struct eap_msg))
	{
		size_t eap_len = payload->len - 4;
		uint8_t *cbor_object = payload->ptr + eap_len;
		rid_c = cbor_object[3];
		payload->len -= 4;
	}
}

/**
 * @brief	Creates the payload for all responses from the Peer
 * @param	iterations Number of iterations related to the chosen EAP method exchange
 * @retval 	The payload created
 */
static struct byte_array create_payload(int iterations)
{
    struct byte_array payload;
	payload.ptr = (uint8_t *)"";
	payload.len = 0;
	struct eap_msg *msg = (struct eap_msg *)eapRespData;

	if (uri_counter == 1)
	{
		size_t eap_len = sizeof(struct eap_msg) + strlen(USER);

		// * Addition of the RID-I identifier to the payload inside a CBOR object
		uint8_t cbor_object[] = { 0xA1, 0x03, 0x41, 0x28 };

		uint8_t *rid_buf = (uint8_t *)malloc(eap_len + sizeof(cbor_object));
		memcpy(rid_buf, eapRespData, eap_len);
		memcpy(rid_buf + eap_len, cbor_object, sizeof(cbor_object));

		payload.ptr = rid_buf;
		payload.len = eap_len + sizeof(cbor_object);
	}
	else if (uri_counter >= 2 && uri_counter < iterations)
	{
		payload.ptr = eapRespData;
		payload.len = ntohs(msg->length);
	}
	else
	{
		payload.ptr = (uint8_t *)"";
		payload.len = strlen((char *)payload.ptr);
	}

	return payload;
}

/**
 * @brief	Preparation of a CoAP response from the Peer
 * @param	rxPDU		Pointer to the PDU related to the request received
 * @param	txPDU 		Pointer to the PDU of the CoAP response to be sent
 * @param	iterations	Number of iterations of the EAP method chosen
 */
static void prepare_CoAP_response(CoapPDU *rxPDU, CoapPDU *txPDU, int iterations)
{
	struct byte_array payload = create_payload(iterations);

	int last_request = (uri_counter == iterations);

    // * Stores the URI string with the format "/a/eap/x"
    uri_counter++;
    char segment_1[] = "a";
    char segment_2[] = "eap";
    char segment_3[BUFFER_CHAR_SIZE];
    snprintf(segment_3, sizeof(segment_3), "%d", uri_counter);

	PRINTF("The uri requested was: %s\n", current_uri);
	// * Simulation of the fact that, in each exchange, a new resource is created and the previous one is erased 
	snprintf(current_uri, sizeof(current_uri), "/%s/%s/%s", segment_1, segment_2, segment_3);
	PRINTF("The uri is now: %s\n", current_uri);

    txPDU->reset();
    txPDU->setVersion(1);
    txPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
    
	if (last_request)
		txPDU->setCode(CoapPDU::COAP_CHANGED);
	else
    	txPDU->setCode(CoapPDU::COAP_CREATED);
	
	txPDU->setToken(rxPDU->getTokenPointer(), rxPDU->getTokenLength());
    txPDU->setMessageID(rxPDU->getMessageID());

	if (!last_request)
	{
		// * URI indicated in the Location-Path which is divided into three segments
		txPDU->addOption(CoapPDU::COAP_OPTION_LOCATION_PATH, strlen(segment_1), (uint8_t *)segment_1);
		txPDU->addOption(CoapPDU::COAP_OPTION_LOCATION_PATH, strlen(segment_2), (uint8_t *)segment_2);
		txPDU->addOption(CoapPDU::COAP_OPTION_LOCATION_PATH, strlen(segment_3), (uint8_t *)segment_3);
	}

    txPDU->setPayload(payload.ptr, payload.len);

	eapResp = FALSE;
}

int run_peer(int run_id)
{
	sleep(3);

	int sock_peer_as_cli, sock_peer;
	char buffer[MAXLINE];

	// * In each run, these values must be reset
	strcpy(current_uri, "/a/eap/1");
	uri_counter = 1;
	rid_c = 0;

	// * sock_peer_as_cli is the socket used by the Peer when it acts as the CoAP client (initial POST)
	TRY_EXPECT(start_coap_endpoint(&sock_peer_as_cli, &sockaddr_peer, PEER_ADDRESS, AUTHENTICATOR_PORT, "Peer"), 0);

	// * sock_peer is the socket used by the Peer for the standard CoAP exchanges
	TRY_EXPECT(start_coap_endpoint(&sock_peer, &sockaddr_peer, PEER_ADDRESS, PEER_PORT, "Peer"), 0);
	
	send_initial_CoAP_request(sock_peer_as_cli);

	EAP__METHOD method = EAP__EDHOC;
	int iterations = eap_get_iterations(method);

	// * First call to the state machine in order to initialize it
	eapRestart = TRUE;
	eap_peer_sm_step(NULL);

	struct context c_peer;

	for (int i = 0; i < iterations; i++)
	{
		CoapPDU *requestPDU = new CoapPDU();

		// * The Peer creates its OSCORE security context after receiving the last EAP Request from the Authenticator
		if (i == iterations - 1)
		{
			enum err ctx = create_oscore_context(&c_peer, rid_c, RID_I, msk_key);
			if (ctx == ok)
			{
				requestPDU = rx(sock_peer, buffer, &sockaddr_auth, "Authenticator");
				uint8_t buf_oscore[512];
				uint32_t buf_oscore_len = sizeof(buf_oscore);

				enum err r = oscore2coap(requestPDU->getPDUPointer(), (uint32_t) requestPDU->getPDULength(),
										 buf_oscore, &buf_oscore_len, &c_peer);
				if (r != ok)
				{
					PRINTF("Error in oscore2coap\n");
				}

				requestPDU = new CoapPDU(buf_oscore, buf_oscore_len);

				if (requestPDU->validate())
				{
					PRINTF("Decrypted OSCORE message\n");
					requestPDU->printHuman();
				}
			}
		} else
			requestPDU = rx(sock_peer, buffer, &sockaddr_auth, "Authenticator");			

		last_mid = requestPDU->getMessageID();
		memcpy(&last_token, requestPDU->getTokenPointer(), sizeof(last_token));

		struct byte_array payload;
		payload.ptr = requestPDU->getPayloadPointer();
		payload.len = requestPDU->getPayloadLength();

		store_rid_c(i, &payload);

		eapReq = TRUE;
		// * Call to the EAP Peer State Machine
		eap_peer_sm_step(payload.ptr);
		
		CoapPDU *responsePDU = new CoapPDU();
		prepare_CoAP_response(requestPDU, responsePDU, iterations);

		// * The last message sent from the Peer is the 2.04 Changed protected with OSCORE, so the Peer
		// * makes the Authenticator know that it has correctly derived the security context
		if (i == iterations - 1)
		{
			uint8_t buf_oscore[512];
			uint32_t buf_oscore_len = sizeof(buf_oscore);

			enum err t = coap2oscore(responsePDU->getPDUPointer(), (uint32_t) responsePDU->getPDULength(),
									 buf_oscore, &buf_oscore_len, &c_peer);

			if (t != ok)
			{
				PRINTF("Error in coap2oscore\n");
			} else
			{
				responsePDU = new CoapPDU(buf_oscore, buf_oscore_len);
				PRINTF("Sending 2.04 Changed protected with OSCORE\n");
			}
		}

		tx(sock_peer, responsePDU, &sockaddr_auth, "Authenticator");
	}

	close(sock_peer_as_cli);
	close(sock_peer);
    
	return 0;
}

int main()
{
	int runs = 5;

	for (int i = 0; i < runs; i++) {
		PRINTF("\n========== RUN NUMBER %d ==========\n", i + 1);
		run_peer(i + 1);
	}

	return 0;
}
