/* 
 *  Copyright (C) Pedro Moreno Sánchez on 25/04/12.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef INCLUDE_H
#define INCLUDE_H

#include <stdint.h>
#include "random.h"


#define DEBUG DEBUG_PRINT

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define MAX_PAYLOAD_LEN 150 //520

// Data types
#define TRUE 1
#define FALSE 0
#define UNSET 0
#define SET 1
#define ERROR 253

// States defined in eap peer sm (rfc 4137)
#define IDLE 0
#define RECEIVED 1
#define SUCCESS 2
#define FAILURE 3
#define NONE 4

// Auxiliar defines
#define FAIL 0
#define RxREQ 1
#define RxSUCCESS 2
#define RxFAILURE 3

#define REQUEST_CODE 1
#define RESPONSE_CODE 2
#define SUCCESS_CODE 3
#define FAILURE_CODE 4
#define IDENTITY 1
#define DUMMY 6
#define EAP_PSK 47
#define EAP_EDHOC 57
#define INIT 7
#define DONE 8
#define CONT 9
#define MAY_CONT 10
#define COND_SUCC 12
#define UNCOND_SUCC 13

#define MSK_LENGTH 64

#define USER "anonymous@um.es"

// Network uint8_t order functions
#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

extern uint8_t msk_key[MSK_LENGTH];

#endif
