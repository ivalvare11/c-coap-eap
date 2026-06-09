#ifndef _EAP_PSK_H
#define _EAP_PSK_H

RCSIDH(eap_psk_h, "$Id$")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "eap.h"
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>


#define PW_PSK_CHALLENGE	1
#define PW_PSK_RESPONSE		2
#define PW_PSK_SUCCESS		3
#define PW_PSK_FAILURE		4
#define PW_PSK_MAX_CODES	4

#define PSK_HEADER_LEN 		4
#define PSK_CHALLENGE_LEN 	16

/*
 ****
 * EAP - PSK does not specify code, id & length but chap specifies them,
 *	for generalization purpose, complete header should be sent
 *	and not just value_size, value and name.
 *	future implementation.
 *
 *	Huh? What does that mean?
 */

/* eap packet structure */
typedef struct psk_packet_t {
/*
	uint8_t	code;
	uint8_t	id;
	uint16_t	length;
*/
	uint8_t	value_size;
	uint8_t	value_name[1];
} psk_packet_t;

typedef struct psk_packet {
	unsigned char	code;
	unsigned char	id;
	unsigned short	length;
	unsigned char	value_size;
	unsigned char	*value;
	char		*name;
} PSK_PACKET;


#endif /*_EAP_PSK_H*/
