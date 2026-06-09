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


#ifndef EAP_PEER
#define EAP_PEER

#include "include.h"
#include "eap-psk.h"
#include "eap-edhoc.h"

#define EAP_MSG_LEN 512


//struct of a eap message
struct eap_msg{
	uint8_t code;
	uint8_t id;
	unsigned short length;
	uint8_t method;
}__attribute__((packed));

//Variables needed in eap peer sm (rfc 4137)
extern uint8_t eapRestart;

extern uint8_t eapReq;

extern uint8_t eapRespData [EAP_MSG_LEN];
extern uint8_t eapResp;

extern uint8_t eapKeyAvailable;
//uint8_t eapKeyData[64]; //MSK length originally is 64
//uint8_t eapKeyLen;

extern uint8_t eapSuccess;
extern uint8_t eapFail;
extern uint8_t eapNoResp;

extern uint8_t selectedMethod;
extern uint8_t methodState;
extern uint8_t decision;
extern uint8_t lastId;
//uint8_t reqMethod;
//uint8_t type_received;

extern uint8_t altAccept;
extern uint8_t altReject;

//Functions
void eap_peer_sm_step(const uint8_t * msg);

#endif
