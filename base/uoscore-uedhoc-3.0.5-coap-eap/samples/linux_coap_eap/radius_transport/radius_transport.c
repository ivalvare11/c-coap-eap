#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "byte_array.h"
#include "common.h"
#include "include.h"
#include "ip_addr.h"
#include "radius_transport.h"

#define CONNECTION_ERROR -1

#define RADIUS_SERVER_ADDRESS "127.0.0.3"
#define RADIUS_CLIENT_PORT 1811

static struct radius_msg *current_radius_msg = NULL;

/**
 * @brief	Translates a hostapd_ip_addr to a sockaddr_in
 * @param	addr		Pointer to the hostapd_ip_addr to be translated
 * @param	sock_addr	Pointer to the resulting sockaddr_in
 * @retval	Generic connection error if failure
 */
int hostapd_ip_addr_to_sockaddr_in(const struct hostapd_ip_addr *addr, struct sockaddr_in *sock_addr)
{
	if (!addr || !sock_addr)
		return CONNECTION_ERROR;
	if (addr->af != AF_INET)
		return CONNECTION_ERROR;

	memset(sock_addr, 0, sizeof(*sock_addr));

	sock_addr->sin_family = addr->af;
	sock_addr->sin_addr = addr->u.v4;
	return 0;
}

/**
 * @brief	Binds the RADIUS client to an IP address and port through a socket
 * @param	client_addr	Pointer to the hostapd_ip_addr of the client
 * @param	client_port	Port corresponding to the RADIUS client
 * @param	force		Whether to force client address
 * @retval	Generic connection error if failure
 */
int radius_bind(const struct hostapd_ip_addr *client_addr, int client_port, int force)
{
	int s;
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1)
	{
		PRINTF("There was an error creating the socket\n");
		return CONNECTION_ERROR;
	}

	// * Configuration of RADIUS client socket address
	struct sockaddr_in cli_addr;
	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_port = htons(client_port);
	if (force && client_addr && client_addr->af == AF_INET)
		cli_addr.sin_addr = client_addr->u.v4;
	else
		cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int associate_socket = bind(s, (struct sockaddr *)&cli_addr, sizeof(cli_addr));
	if (associate_socket < 0)
	{
		PRINTF("There was an error associating the socket\n");
		close(s);
		return CONNECTION_ERROR;
	}

	return s;
}

// * Simplification of "int radius_client_init_auth(...)"
int radius_client_init_auth(struct radius_client_data *radius)
{
	if (!radius || !radius->conf || !radius->conf->auth_server)
		return CONNECTION_ERROR;

	// * Connection of the RADIUS client to a socket
	int s = radius_bind(&radius->conf->client_addr, RADIUS_CLIENT_PORT, radius->conf->force_client_addr);
	radius->auth_sock = s;

	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));

	// * Configuration of the RADIUS server related to the RADIUS client
	struct hostapd_radius_server *srv = radius->conf->auth_server;
	int translation_addr = hostapd_ip_addr_to_sockaddr_in(&srv->addr, &sock_addr);
	if (translation_addr < 0)
	{
		PRINTF("Error translating address\n");
		hostapd_parse_ip_addr(RADIUS_SERVER_ADDRESS, &srv->addr);
		sock_addr.sin_addr = srv->addr.u.v4;
	}
	sock_addr.sin_port = htons(srv->port);

	radius->auth_server_sockaddr = sock_addr;
	radius->auth_shared_secret = srv->shared_secret;
	radius->auth_shared_secret_len = srv->shared_secret_len;

	return 0;
}

void deinit_radius_client(struct radius_client_data *radius)
{
	if (!radius)
		return;

	// * Simplification of "void radius_close_auth_socket"
	if (radius->auth_sock >= 0)
	{
		close(radius->auth_sock);
		radius->auth_sock = -1;
	}

	struct radius_msg_list *requests = radius->pending_requests;
	while (requests)
	{
		struct radius_msg_list *next = requests->next;
		radius_msg_free(requests->msg);
		free(requests);
		requests = next;
	}

	os_free(radius);
}

struct radius_client_data *init_radius_client(void *ctx, struct hostapd_radius_servers *conf)
{
	struct radius_client_data *radius = (struct radius_client_data *)os_zalloc(sizeof(*radius));
	if (radius == NULL)
		return NULL;

	radius->ctx = ctx;
	radius->conf = conf;
	radius->auth_sock = -1;
	radius->pending_requests = NULL;

	radius->state_attr.ptr = NULL;
	radius->state_attr.len = 0;

	if (conf->auth_server && radius_client_init_auth(radius) == CONNECTION_ERROR)
	{
		deinit_radius_client(radius);
		return NULL;
	}

	return radius;
}

// * Simplification of "int radius_client_send(..., RadiusType msg_type, const u8 *addr)""
int radius_send(struct radius_client_data *radius, struct radius_msg *msg)
{
	if (!radius || !radius->conf || !radius->conf->auth_server)
	{
		PRINTF("Invalid RADIUS client or configuration\n");
		return CONNECTION_ERROR;
	}

	if (radius->auth_sock < 0)
	{
		if (radius_client_init_auth(radius) == CONNECTION_ERROR)
		{
			PRINTF("Failed to initialize RADIUS socket\n");
			return CONNECTION_ERROR;
		}
	}

	struct radius_hdr *hdr = radius_msg_get_hdr(msg);
	if (!hdr)
	{
		PRINTF("Invalid RADIUS message header\n");
		return CONNECTION_ERROR;
	}

	struct hostapd_radius_server *srv = radius->conf->auth_server;

	if (!srv->shared_secret || srv->shared_secret_len == 0)
	{
		PRINTF("RADIUS shared secret not configured\n");
		return CONNECTION_ERROR;
	}

	if (radius_msg_finish(msg, srv->shared_secret, srv->shared_secret_len) < 0)
	{
		PRINTF("Failed to finalize RADIUS message\n");
		return CONNECTION_ERROR;
	}

	struct wpabuf *buf = radius_msg_get_buf(msg);
	if (!buf)
	{
		PRINTF("Failed to get RADIUS message buffer\n");
		return CONNECTION_ERROR;
	}

	int sending = sendto(radius->auth_sock, wpabuf_head(buf), wpabuf_len(buf), 0, (struct sockaddr *)&radius->auth_server_sockaddr, sizeof(radius->auth_server_sockaddr));

	if (sending < 0)
	{
		PRINTF("Failed to send RADIUS message\n");
		return CONNECTION_ERROR;
	}

	// * We store the requests for which there is no response received yet
	struct radius_msg_list *requests = (struct radius_msg_list *)os_zalloc(sizeof(*requests));
	requests->msg = msg;
	requests->identifier = hdr->identifier;
	requests->next = radius->pending_requests;
	radius->pending_requests = requests;

	return 0;
}

/**
 * @brief	Extracts the MSK of an Access-Accept message concatenating the Send-Key and Recv-Key
 * @param	radius	The client who has received the Access-Accept message
 */
void extract_msk(struct radius_client_data *radius)
{
	// * The current RADIUS message is in fact an Access-Accept message
	if (!radius || !current_radius_msg)
		return;

	PRINTF("Extracting MSK...\n");

	// * Free previous MSK
	if (radius->msk)
	{
		free(radius->msk);
		radius->msk = NULL;
		radius->msk_len = 0;
	}

	// * Last Access-Request pending
	struct radius_msg *last_request = radius->pending_requests ? radius->pending_requests->msg : NULL;

	if (!last_request)
	{
		PRINTF("There is no Access-Request pending\n");
		return;
	}

	struct radius_ms_mppe_keys *keys = radius_msg_get_ms_keys(current_radius_msg, last_request, radius->auth_shared_secret, radius->auth_shared_secret_len);

	if (!keys || !keys->send || !keys->recv)
	{
		PRINTF("Failed to decrypt MS-MPPE keys\n");
		if (keys)
			os_free(keys);
		return;
	}

	// * MSK = Recv-Key || Send-Key
	radius->msk_len = keys->send_len + keys->recv_len;
	radius->msk = malloc(radius->msk_len);
	memcpy(radius->msk, keys->recv, keys->recv_len);
	memcpy(radius->msk + keys->recv_len, keys->send, keys->send_len);

	if (keys->send)
		free(keys->send);
	if (keys->recv)
		free(keys->recv);
	os_free(keys);
}

void radius_receive(struct radius_client_data *radius)
{
	if (!radius || radius->auth_sock < 0)
	{
		PRINTF("Invalid RADIUS client or socket\n");
		return;
	}

	uint8_t buf[RADIUS_MAX_MSG_LEN];
	struct sockaddr_in serv_addr;
	socklen_t serv_addr_len = sizeof(serv_addr);

	int receiving = recvfrom(radius->auth_sock, buf, sizeof(buf), 0, (struct sockaddr *)&serv_addr, &serv_addr_len);

	if (receiving < 0)
	{
		PRINTF("Failed to receive RADIUS message\n");
		close(radius->auth_sock);
		return;
	}

	struct radius_msg *msg = radius_msg_parse(buf, receiving);
	if (!msg)
	{
		PRINTF("Failed to parse RADIUS message\n");
		return;
	}

	struct radius_hdr *hdr = radius_msg_get_hdr(msg);

	// * Recognition of the RADIUS message code received
	switch (hdr->code)
	{
		case RADIUS_CODE_ACCESS_ACCEPT:
			PRINTF("Access-Accept received\n");
			break;
		case RADIUS_CODE_ACCESS_REJECT:
			PRINTF("Access-Reject received\n");
			break;
		case RADIUS_CODE_ACCESS_CHALLENGE:
			PRINTF("Access-Challenge received\n");
			break;
		default:
			PRINTF("Unknown RADIUS code: %d\n", hdr->code);
			break;
	}

	struct radius_msg_list *previous_requests = NULL;
	struct radius_msg_list *requests = radius->pending_requests;

	// * If we receive a response from a request matching its identifier, that request is no longer pending
	while (requests)
	{
		if (requests->identifier == hdr->identifier)
			break;

		previous_requests = requests;
		requests = requests->next;
	}

	if (current_radius_msg)
		radius_msg_free(current_radius_msg);

	current_radius_msg = msg;

	// * Process Access-Challenge to store the state
	if (hdr->code == RADIUS_CODE_ACCESS_CHALLENGE)
	{
		size_t state_len = radius_msg_get_attr(
			current_radius_msg, RADIUS_ATTR_STATE, NULL, 0);
		if (state_len > 0)
		{
			if (radius->state_attr.ptr)
				free(radius->state_attr.ptr);

			radius->state_attr.ptr = malloc(state_len);
			radius->state_attr.len = radius_msg_get_attr(current_radius_msg, RADIUS_ATTR_STATE, radius->state_attr.ptr, state_len);
			PRINTF("Stored RADIUS state attribute (%u bytes)\n", radius->state_attr.len);
		}
	}

	// * Process Access-Accept to extract MSK
	if (hdr->code == RADIUS_CODE_ACCESS_ACCEPT)
		extract_msk(radius);

	if (requests)
	{
		if (previous_requests)
			previous_requests->next = requests->next;
		else
			radius->pending_requests = requests->next;

		radius_msg_free(requests->msg);
		os_free(requests);
	} else
		PRINTF("No pending request for Identifier = %d\n", hdr->identifier);
}

struct byte_array get_eap_from_radius_msg()
{
	struct byte_array eap_msg;
	eap_msg.ptr = NULL;
	eap_msg.len = 0;

	if (!current_radius_msg)
		return eap_msg;

	struct wpabuf *buf = radius_msg_get_buf(current_radius_msg);
	if (!buf)
		return eap_msg;

	// * Pointer to the start of the RADIUS packet
	const uint8_t *radius_packet = wpabuf_head(buf);
	size_t radius_packet_len = wpabuf_len(buf);

	if (radius_packet_len <= RADIUS_MIN_MSG_LEN)
	{
		PRINTF("RADIUS packet too short\n");
		return eap_msg;
	}

	// * RADIUS attributes start after this offset
	size_t offset = RADIUS_MIN_MSG_LEN;

	uint8_t *buffer = malloc(RADIUS_MAX_MSG_LEN);
	if (!buffer)
		return eap_msg;

	// * Length of the EAP message (fragmentation included)
	size_t buffer_len = 0;

	// * For all RADIUS attributes (Type, Length, Value)
	while (offset + 2 <= radius_packet_len)
	{
		uint8_t attr_type = radius_packet[offset];
		uint8_t attr_len = radius_packet[offset + 1];

		if (attr_len < 2 || offset + attr_len > radius_packet_len)
		{
			PRINTF("Invalid or truncated attribute\n");
			break;
		}

		// * Value points to the first byte of the attribute data
		const uint8_t *value = radius_packet + offset + 2;
		size_t value_len = attr_len - 2;

		if (attr_type == RADIUS_ATTR_EAP_MESSAGE)
		{
			if (buffer_len + value_len > RADIUS_MAX_MSG_LEN)
			{
				PRINTF("RADIUS EAP total length exceeds buffer\n");
				free(buffer);
				return eap_msg;
			}

			// * Possible fragments of the EAP message attribute are concatenated
			memcpy(buffer + buffer_len, value, value_len);
			buffer_len += value_len;
		}

		// * Next attribute
		offset += attr_len;
	}

	if (buffer_len == 0)
	{
		free(buffer);
		PRINTF("No EAP-Message attributes found\n");
		return eap_msg;
	}

	eap_msg.ptr = buffer;
	eap_msg.len = buffer_len;
	PRINTF("Extracted full EAP length = %zu bytes\n", buffer_len);
	return eap_msg;
}

int radius_send_access_request(struct radius_client_data *radius, const uint8_t *payload, size_t payload_len)
{
	if (!radius || !payload || payload_len == 0)
		return CONNECTION_ERROR;

	struct radius_msg *msg;
	u8 identifier = 1;

	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, identifier);
	if (!msg)
	{
		PRINTF("Failed to create Access-Request\n");
		return CONNECTION_ERROR;
	}

	if (radius_msg_make_authenticator(msg) < 0)
	{
		PRINTF("Failed to generate authenticator\n");
		radius_msg_free(msg);
		return CONNECTION_ERROR;
	}

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, (u8 *)USER, strlen(USER)))
	{
		PRINTF("Failed to add username\n");
		radius_msg_free(msg);
		return CONNECTION_ERROR;
	}

	// * Here the EAP message is encapsulated
	if (!radius_msg_add_eap(msg, payload, payload_len))
	{
		PRINTF("Failed to add EAP message to Access-Request\n");
		radius_msg_free(msg);
		return CONNECTION_ERROR;
	}

	if (radius->state_attr.len > 0 && radius->state_attr.ptr != NULL)
	{
		if (!radius_msg_add_attr(msg, RADIUS_ATTR_STATE, radius->state_attr.ptr, radius->state_attr.len))
		{
			PRINTF("Failed to add State attribute to Access-Request\n");
			radius_msg_free(msg);
			return CONNECTION_ERROR;
		}
		PRINTF("Included State attribute in Access-Request message to be sent\n");
	}

	if (radius_send(radius, msg) < 0)
	{
		PRINTF("Error sending Access-Request\n");
		radius_msg_free(msg);
		return CONNECTION_ERROR;
	}

	PRINTF("Access-Request was sent\n");

	return 0;
}
