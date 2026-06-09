#ifndef RADIUS_TRANSPORT_H

    #define RADIUS_TRANSPORT_H

    #include <netinet/in.h>
    #include <stdint.h>
    #include <stddef.h>

    #include "common.h"
    #include "radius.h"
	#include "radius_client.h"

    // * Simplification of the radius_msg_list structure
    struct radius_msg_list
    {
        struct radius_msg *msg;
        u8 identifier;
        struct radius_msg_list *next;
    };

    // * Simplification of the radius_client_data structure
    struct radius_client_data
    {
        void *ctx;
        struct hostapd_radius_servers *conf;
        int auth_sock;
        struct sockaddr_in auth_server_sockaddr;
        u8 *auth_shared_secret;
        size_t auth_shared_secret_len;

        // * Stores the identifier of a request until its response is received
        struct radius_msg_list *pending_requests;

        //* Attribute for keeping the state during a connection with the RADIUS server
        struct byte_array state_attr;

        uint8_t *msk;
        size_t msk_len;
    };

    // * Simplification of "void radius_client_deinit(...)"
    void deinit_radius_client(struct radius_client_data *radius);

    // * Simplification of "struct radius_client_data *radius_client_init(...)"
    struct radius_client_data *init_radius_client(void *ctx, struct hostapd_radius_servers *conf);

    // * Simplification of "void radius_client_receive(int sock, void *eloop_ctx, void *sock_ctx)"
    void radius_receive(struct radius_client_data *radius);

    /**
    * @brief	Obtains the EAP message that is encapsulated in the attribute of a RADIUS message
    * @retval	The EAP message from the RADIUS packet
    */
    struct byte_array get_eap_from_radius_msg();

    /**
     * @brief   Sending of a RADIUS Access-Request message
     * @param   radius      RADIUS client data from the client that sends the message
     * @param   payload     The EAP message located in the CoAP PDU that the RADIUS client receives
     * @param   payload_len Length of the previous EAP message
     * @retval  Generic connection error if failure
     */
    int radius_send_access_request(struct radius_client_data *radius, const uint8_t *payload, size_t payload_len);

#endif