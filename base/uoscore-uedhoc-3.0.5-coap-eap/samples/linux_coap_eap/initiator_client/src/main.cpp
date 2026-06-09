/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern "C" {
	#include "sock.h"
	#include "common.h"
	#include "eap_methods.h"
	#include "eap-peer.h"
	#include "ip_addr.h"
	#include "oscore.h"
	#include "oscore_context.h"
	#include "radius.h"
	#include "radius_client.h"
	#include "radius_transport.h"
}

#include "cantcoap.h"
#include "coap_transport.h"

#define RID_C 20

#define CONNECTION_ERROR -1

#define PEER_ADDRESS "127.0.0.1"
#define AUTHENTICATOR_ADDRESS "127.0.0.2"
#define AUTHENTICATOR_PORT 5682
#define PEER_PORT 5683

#define RADIUS_CLIENT_ADDRESS "127.0.0.2"
#define RADIUS_SERVER_ADDRESS "127.0.0.3"
#define RADIUS_CLIENT_PORT 1811
#define RADIUS_SERVER_PORT 1812
#define SECRET "testing123"

SocketAddress sockaddr_auth;
SocketAddress sockaddr_peer;

static uint8_t rid_i = 0;
static uint16_t last_mid = 0;
static uint32_t last_token = 0;

/**
 * @brief	Obtains the URI from the payload of a CoAP Protocol Data Unit
 * @param	pdu	Pointer to the PDU whose payload is extracted
 * @retval	The content of the payload as a readable string
 */
static char *get_uri_from_payload(CoapPDU *pdu)
{
	struct byte_array payload;
	payload.ptr = pdu->getPayloadPointer();
	payload.len = pdu->getPayloadLength();

	char *uri = (char *)malloc(payload.len + 1);
	memcpy(uri, payload.ptr, payload.len);
	uri[payload.len] = '\0';

	return uri;
}

/**
 * @brief	Builds an EAP Request/Identity message with a given id
 * @retval	The EAP message formatted as the payload of a PDU
 */
static struct byte_array build_eap_request_identity()
{
	static uint8_t buffer[sizeof(struct eap_msg)];

	struct eap_msg *msg = (struct eap_msg *)buffer;
	msg->code = REQUEST_CODE;
	msg->id = 1;
	msg->length = htons(sizeof(struct eap_msg));
	msg->method = IDENTITY;

	struct byte_array payload;
	payload.ptr = buffer;
	payload.len = sizeof(struct eap_msg);

	return payload;
}

/**
 * @brief	Creates the payload for all requests from the Authenticator
 * @param	uri			The URI associated with the request in process to be sent
 * @param	iterations	Number of iterations related to the chosen EAP method exchange
 * @retval 	The payload created
 */
static struct byte_array create_payload(char *uri, int iterations)
{
	struct byte_array payload;
	payload.ptr = (uint8_t *)"";
	payload.len = 0;

	int uri_number = 0;
	sscanf(uri, "/a/eap/%d", &uri_number);

	if (uri_number == 1)
	{
		struct byte_array eap_payload = build_eap_request_identity();

		// * Addition of the RID-C identifier to the payload inside a CBOR object
		uint8_t cbor_object[] = { 0xA1, 0x02, 0x41, 0x14 };
		uint8_t *buffer_rid = (uint8_t *)malloc(eap_payload.len + sizeof(cbor_object));
		memcpy(buffer_rid, eap_payload.ptr, eap_payload.len);
		memcpy(buffer_rid + eap_payload.len, cbor_object, sizeof(cbor_object));

		payload.ptr = buffer_rid;
		payload.len = eap_payload.len + sizeof(cbor_object);
	} else if (uri_number >= 2 && uri_number <= iterations)
	{
		payload = get_eap_from_radius_msg();
		PRINTF("Using EAP message from RADIUS server as CoAP payload\n");
		for (size_t i = 0; i < payload.len; i++)
		{
			PRINTF("%02X", payload.ptr[i]);
		}
		PRINTF("\n\n");
	} else
	{
		payload.ptr = (uint8_t *)"";
		payload.len = strlen((char *)payload.ptr);
	}

	return payload;
}

/**
 * @brief	Builds the PDU of a CoAP POST request
 * @param	pdu			Pointer to the PDU of the CoAP packet to send
 * @param	uri			The URI associated with the request in process to be sent
 * @param	iterations 	Number of iterations related to the chosen EAP method exchange
 */
static void build_pdu(CoapPDU *pdu, char *uri, int iterations)
{
	// * Incremental treatment for message ID and token
	last_mid++;
	last_token++;
	uint16_t mid = last_mid;
	uint32_t token = last_token;

	pdu->reset();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_POST);
	pdu->setToken((uint8_t *)&token, sizeof(token));
	pdu->setMessageID(mid);
	pdu->setURI(uri, strlen(uri));

	struct byte_array payload = create_payload(uri, iterations);
	pdu->setPayload(payload.ptr, payload.len);
}

/**
 * @brief	In the first exchange of the flow, the Authenticator stores the RID-I from the Peer
 * @param	i		Number of the iteration (should be equal to 0, that is, when the Authenticator receives the EAP Response/Identity)
 * @param	payload	The payload of the CoAP message that encapsulates the EAP Response/Identity
 */
void store_rid_i(int i, struct byte_array *payload)
{
	size_t eap_len = sizeof(struct eap_msg) + strlen(USER);
	// * Waiting EAP message + 4 bytes from CBOR object
	if (i == 0 && payload->len == eap_len + 4)
	{
		uint8_t *cbor_object = payload->ptr + eap_len;
		rid_i = cbor_object[3];
		payload->len -= 4;
	}
}

/**
 * @brief	Configures the RADIUS server and client endpoints so they are ready for communication
 * @param radius	RADIUS data associated with the client entity
 */
void configure_radius_endpoints(struct radius_client_data **radius)
{
	// * Configuration of the RADIUS server
	struct hostapd_radius_server *auth_srv = (struct hostapd_radius_server *)os_zalloc(sizeof(*auth_srv));

	hostapd_parse_ip_addr(RADIUS_SERVER_ADDRESS, &auth_srv->addr);
	auth_srv->port = RADIUS_SERVER_PORT;
	auth_srv->shared_secret = (u8 *)strdup(SECRET);
	auth_srv->shared_secret_len = strlen((char *)auth_srv->shared_secret);

	struct hostapd_radius_servers *conf = (struct hostapd_radius_servers *)os_zalloc(sizeof(*conf));
	conf->auth_server = auth_srv;
	conf->num_auth_servers = 1;
	conf->force_client_addr = 1;

	// * Configuration and initialization of the RADIUS client
	hostapd_parse_ip_addr(RADIUS_CLIENT_ADDRESS, &conf->client_addr);
	*radius = init_radius_client(NULL, conf);
}

/**
 * @brief	Updates the URI with the one which is going to be used in the next request
 * @param	pdu	Pointer to the PDU of the CoAP response received by the Authenticator
 * @param	uri	Pointer to the object that represents the URI for each iteration
 */
static void update_uri(CoapPDU *pdu, char *uri)
{
	char current_uri[MAXLINE] = "/";
	int numOptions = pdu->getNumOptions();
	CoapPDU::CoapOption *options = pdu->getOptions();

	for (int j = 0; j < numOptions; j++)
	{
		if (options[j].optionNumber == CoapPDU::COAP_OPTION_LOCATION_PATH)
		{
			strncat(current_uri, (char *)options[j].optionValuePointer,	options[j].optionValueLength);
			// * 2 ("/" + "\0")
			strncat(current_uri, "/", 2);
		}
	}

	int current_uri_len = strlen(current_uri);
	if (current_uri_len > 0 && current_uri[current_uri_len - 1] == '/')
		current_uri[current_uri_len - 1] = '\0';

	if (strlen(current_uri) > 1)
	{
		strcpy(uri, current_uri);
		PRINTF("The next uri is: %s\n", uri);
	}
}

/**
 * @brief	Runs the code through which the EAP Authenticator completes the CoAP-EAP flow
 */
int run_authenticator(int run_id)
{
	int sock_auth_as_srv, sock_auth;
	char buffer[MAXLINE];

	// * For each run, this identifier is reset
	rid_i = 0;

	// * sock_auth_as_srv is the socket used by the Authenticator when it acts as the CoAP server (initial POST)
	TRY_EXPECT(start_coap_endpoint(&sock_auth_as_srv, &sockaddr_auth, AUTHENTICATOR_ADDRESS, PEER_PORT, "Authenticator"), 0);

	// * sock_auth is the socket used by the Authenticator for the standard CoAP exchanges
	TRY_EXPECT(start_coap_endpoint(&sock_auth, &sockaddr_auth, AUTHENTICATOR_ADDRESS, AUTHENTICATOR_PORT, "Authenticator"), 0);

	PRINTF("Waiting for initial POST from Peer...\n");

	CoapPDU *initialPDU = rx(sock_auth_as_srv, buffer, &sockaddr_peer, "Peer");

	last_mid = initialPDU->getMessageID();
	memcpy(&last_token, initialPDU->getTokenPointer(), sizeof(last_token));

	char *uri = get_uri_from_payload(initialPDU);
	delete (initialPDU);

	char next_uri[MAXLINE];
	strcpy(next_uri, uri);
	free(uri);

	EAP__METHOD method = EAP__EDHOC;
	int iterations = eap_get_iterations(method);

	// * Configuration of the destination endpoint
	configure_sock_addr(&sockaddr_peer, PEER_ADDRESS, PEER_PORT);

	// * OSCORE, RADIUS and URI contexts are isolated for each run
	struct radius_client_data *radius = NULL;
	struct context c_auth;

	for (int i = 0; i < iterations; i++)
	{
		CoapPDU *requestPDU = new CoapPDU();
		build_pdu(requestPDU, next_uri, iterations);

		// * The Authenticator creates its OSCORE security context before relaying the EAP Success message
		if (i == iterations - 1)
		{
			enum err ctx = create_oscore_context(&c_auth, rid_i, RID_C, radius->msk);
			if (ctx == ok)
			{
				uint8_t buf_oscore[512];
				uint32_t buf_oscore_len = sizeof(buf_oscore);

				enum err c = coap2oscore(requestPDU->getPDUPointer(), (uint32_t)requestPDU->getPDULength(), buf_oscore, &buf_oscore_len, &c_auth);

				if (c != ok)
				{
					PRINTF("Error in coap2oscore\n");
				}
				else
				{
					requestPDU = new CoapPDU(buf_oscore, buf_oscore_len);
					PRINTF("Sending EAP Success protected with OSCORE\n");
				}
			}
		}

		tx(sock_auth, requestPDU, &sockaddr_peer, "Peer");

		CoapPDU *responsePDU = rx(sock_auth, buffer, &sockaddr_peer, "Peer");

		last_mid = responsePDU->getMessageID();
		memcpy(&last_token, responsePDU->getTokenPointer(), sizeof(last_token));

		if (i == iterations - 1)
		{
			uint8_t buf_oscore[512];
			uint32_t buf_oscore_len = sizeof(buf_oscore);

			enum err r = oscore2coap(responsePDU->getPDUPointer(), responsePDU->getPDULength(), buf_oscore, &buf_oscore_len, &c_auth);

			if (r != ok)
			{
				PRINTF("Error in oscore2coap\n");
			} else
			{
				responsePDU = new CoapPDU(buf_oscore, buf_oscore_len);
				if (responsePDU->validate())
				{
					PRINTF("Decrypted OSCORE message\n");
					responsePDU->printHuman();
				}
			}

			PRINTF("\nThe EAP authentication process has ended\n");
			break;
		}

		struct byte_array payload;
		payload.ptr = responsePDU->getPayloadPointer();
		payload.len = responsePDU->getPayloadLength();

		store_rid_i(i, &payload);

		if (i == 0)
			configure_radius_endpoints(&radius);

		// * In each iteration, the RADIUS client relays EAP messages within an Access-Request
		if (radius)
		{
			radius_send_access_request(radius, payload.ptr, payload.len);

			// * Timeout if RADIUS server is not found
			struct timeval tv;
			tv.tv_sec = 3;
			tv.tv_usec = 0;
			setsockopt(radius->auth_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			radius_receive(radius);
		} else
		{
			PRINTF("There was an error initializing RADIUS client\n");
		}

		update_uri(responsePDU, next_uri);

		delete responsePDU;
	}

	if (radius)
		deinit_radius_client(radius);

	close(sock_auth_as_srv);
	close(sock_auth);

	return 0;
}

int main()
{
	int runs = 5;

	for (int i = 0; i < runs; i++) {
		PRINTF("\n========== RUN NUMBER %d ==========\n", i + 1);
		run_authenticator(i + 1);
	}

	return 0;
}
