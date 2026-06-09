/* Copyright (c) 2012, Pedro Moreno Sánchez
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the University of Murcia nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include <stdio.h>
#include <string.h>
#include "eap-peer.h"

#define reqId ((struct eap_msg *)msg)->id
#define reqMethod ((struct eap_msg *)msg)->method

uint8_t eapRestart = 0;
uint8_t eapReq = 0;
uint8_t eapRespData[EAP_MSG_LEN];
uint8_t eapResp = 0;
uint8_t eapKeyAvailable = 0;
uint8_t eapSuccess = 0;
uint8_t eapFail = 0;
uint8_t eapNoResp = 0;
uint8_t selectedMethod = 0;
uint8_t methodState = 0;
uint8_t decision = 0;
uint8_t lastId = 0;
uint8_t altAccept = 0;
uint8_t altReject = 0;


static void buildIdentity(const uint8_t id)
{	
	struct eap_msg *msg = (struct eap_msg *)eapRespData; 

	msg->code = RESPONSE_CODE;
	msg->id = id;
	msg->length = HTONS((sizeof(struct eap_msg) + strlen((char *)USER)));
	msg->method = IDENTITY;

	memcpy(eapRespData + sizeof(struct eap_msg), USER, strlen((char *)USER));
}

// EAP Peer state machine step function
void eap_peer_sm_step(const uint8_t* msg)
{	
	static struct data_edhoc *edhoc_data = NULL;
	// Initialize state
	if (eapRestart)
	{	
		selectedMethod = NONE;
		methodState = NONE;
		decision = FAIL;
		lastId = NONE;
		eapSuccess = FALSE;
		eapFail = FALSE;
		eapKeyAvailable = FALSE;

		// Initialization out of standard
		eapReq = FALSE;
		eapResp = FALSE;
		eapNoResp = FALSE;
		memset(eapRespData, 0, EAP_MSG_LEN);

		if (edhoc_data != NULL)
			edhoc_data = NULL;

		edhoc_data = initMethodEap_edhoc();

		// initMethodEap_psk();

		eapRestart = FALSE;
		return;
	}

	if (msg == NULL)
		return;

	// Received state
	if (eapReq)
	{
		if ( (((struct eap_msg *)msg)->code == SUCCESS_CODE) && (reqId == lastId) && (decision!=FAIL) )
			goto _SUCCESS;
		
		else if (methodState != CONT && ( ( (((struct eap_msg *)msg)->code == FAILURE_CODE) && decision != UNCOND_SUCC ) || ( (((struct eap_msg *)msg)->code == SUCCESS_CODE) && decision==FAIL ) ) && (reqId == lastId))
			goto _FAILURE;
		
		else if ( (((struct eap_msg *)msg)->code == REQUEST_CODE) && reqId == lastId )
			// Retransmit state
			goto _SEND_RESPONSE;

		else if ( (((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId != lastId) && (selectedMethod == NONE) && (reqMethod == IDENTITY) )
		{
			buildIdentity(reqId);
			goto _SEND_RESPONSE;
		}
		
		else if ( (((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId != lastId) && (selectedMethod == NONE) && (reqMethod != IDENTITY) )
		{
			// GET_METHOD STATE
			if (reqMethod == EAP_PSK)
			{
				selectedMethod = reqMethod;
				methodState = INIT;
			}
			else if (reqMethod == EAP_EDHOC)
			{
				selectedMethod = reqMethod;
				methodState = INIT;
			}
			if (selectedMethod == reqMethod) goto _METHOD;
			else goto _SEND_RESPONSE;
		}
	
		else if ( (((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId != lastId) && (reqMethod == selectedMethod) && (methodState != DONE) )
			goto _METHOD;
		
		else goto _DISCARD;
	}
	else if ((altAccept && decision != FAIL)) goto _SUCCESS;

	else if (altReject || (altAccept && methodState != CONT && decision == FAIL)) goto _FAILURE;
	
	else goto _DISCARD;

_FAILURE:
	printf("FAILURE state\n");
	eapFail = TRUE;
	return;

_SUCCESS:
	printf("SUCCESS state\n");
	eapSuccess = TRUE;
	return;

_METHOD:
	if (selectedMethod == EAP_EDHOC)
	{
		if (check_edhoc(msg))
		{
			process_edhoc(edhoc_data, msg, &methodState, &decision);
			buildResp_edhoc(edhoc_data, eapRespData, reqId);
			goto _SEND_RESPONSE;
		}
	}
	else if (selectedMethod == EAP_PSK)
	{
		if (check_psk(msg))
		{
			process_psk(msg, &methodState, &decision);
			buildResp_psk(eapRespData, reqId);
			// eapKeyAvailable is directly set in EAP-PSK method
			goto _SEND_RESPONSE;
		}
	}
	else goto _DISCARD;
	
_SEND_RESPONSE:
	printf("SEND_RESPONSE state\n");
	lastId = reqId;
	eapReq = FALSE;
	eapResp = TRUE;
	return;

_DISCARD:
	printf("DISCARD state\n");
	eapReq = FALSE;
	eapNoResp = TRUE;
	return;
}

