#ifndef COAP_TRANSPORT_H

    #define COAP_TRANSPORT_H

    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include "cantcoap.h"

    struct SocketAddress 
    {
        struct sockaddr_in addr;
        socklen_t addr_len;
    };

    /**
     * @brief	Configuration that assigns an address and port to a CoAP endpoint
     * @param	sockaddr    Pointer to the socket address related to the CoAP endpoint
     * @param	ipaddr      Internet address to be assigned to the socket
     * @param	port	    Port to be assigned to the socket
     * @retval	Generic connection error if failure
    */
    int configure_sock_addr(SocketAddress *sockaddr, const char *ipaddr, int port);

    /**
    * @brief	Initializes a socket for a CoAP endpoint
    * @param	sockfd      Pointer to the socket file descriptor
    * @param    sockaddr    Pointer to the socket address related to the CoAP endpoint
    * @param	ipaddr	    Internet address to be assigned to the socket
    * @param	port	    Port to be assigned to the socket
    * @param    name        Name of the CoAP endpoint (server or client)
    * @retval	Generic connection error if failure
    */
    int start_coap_endpoint(int *sockfd, SocketAddress *sockaddr, const char *ipaddr, int port, const char *name);

    /**
     * @brief	Method to send data transported by CoAP
     * @param	sock            Socket used to send the data
     * @param   pdu             PDU built that is going to be sent and contains the data in its payload
     * @param   dst_sockaddr    Socket address associated with the data recipient
     * @param	dst_name        Name of the data recipient
     * @retval	Generic connection error if failure
     */
    int tx(int sock, CoapPDU *pdu, SocketAddress *dst_sockaddr, const char *dst_name);

    /**
     * @brief	Method to receive data transported by CoAP
     * @param	sock	        Socket used to receive the data
     * @param	buffer	        Buffer used to read the data received
     * @param   src_sockaddr    Socket address associated with the data issuer
     * @param	src_name        Name of the data issuer
     * @retval	The PDU received
     */
    CoapPDU *rx(int sock, char *buffer, SocketAddress *src_sockaddr, const char *src_name);

#endif