#include <stdio.h>
#include <string.h>

extern "C"
{
	#include "print_util.h"
	#include "sock.h"
}

#include "coap_transport.h"

#define CONNECTION_ERROR -1

int configure_sock_addr(SocketAddress *sockaddr, const char *ipaddr, int port)
{
	sockaddr->addr_len = sizeof(sockaddr->addr);
	memset(&sockaddr->addr, 0, sockaddr->addr_len);
	sockaddr->addr.sin_family = AF_INET;
	sockaddr->addr.sin_port = htons(port);

	int store_sock_addr = inet_pton(AF_INET, ipaddr, &sockaddr->addr.sin_addr);
	if (store_sock_addr < 0)
	{
		PRINTF("There was an error assigning the IP address %s\n", ipaddr);
		return CONNECTION_ERROR;
	}

	return 0;
}

int start_coap_endpoint(int *sockfd, SocketAddress *sockaddr, const char *ipaddr, int port, const char *name)
{
	int s;

	// * Socket UDP
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1)
	{
		PRINTF("There was an error creating a socket for the %s\n", name);
		return CONNECTION_ERROR;
	}

	configure_sock_addr(sockaddr, ipaddr, port);

	int associate_socket = bind(s, (struct sockaddr *)&sockaddr->addr, sockaddr->addr_len);
	if (associate_socket < 0)
	{
		PRINTF("There was an error associating a socket to the %s\n", name);
		return CONNECTION_ERROR;
	}

	*sockfd = s;
	PRINTF("%s bound to %s:%d\n", name, ipaddr, port);
	return 0;
}

int tx(int sock, CoapPDU *pdu, SocketAddress *dst_sockaddr, const char *dst_name)
{
	int sending;
	sending = sendto(sock, pdu->getPDUPointer(), pdu->getPDULength(), 0, (struct sockaddr *)&dst_sockaddr->addr, dst_sockaddr->addr_len);

	if (sending < 0)
	{
		PRINTF("Error sending request to the %s\n", dst_name);
		return CONNECTION_ERROR;
	}

	PRINTF("\n=====================================================\n");
	PRINTF("Message sent to the %s\n", dst_name);

	if (pdu->validate())
		pdu->printHuman();

	delete pdu;

	return 0;
}

CoapPDU *rx(int sock, char *buffer, SocketAddress *src_sockaddr, const char *src_name)
{
	CoapPDU *pdu;
	int receiving;
	receiving = recvfrom(sock, buffer, MAXLINE, 0, (struct sockaddr *)&src_sockaddr->addr, &src_sockaddr->addr_len);

	if (receiving < 0)
	{
		PRINTF("Error receiving message from the %s\n", src_name);
		return NULL;
	}

	PRINTF("We received %d bytes\n", receiving);
	pdu = new CoapPDU((uint8_t *)buffer, receiving);
	PRINTF("\n=====================================================\n");
	PRINTF("Message received from the %s\n", src_name);

	if (pdu->validate())
		pdu->printHuman();

	return pdu;
}
