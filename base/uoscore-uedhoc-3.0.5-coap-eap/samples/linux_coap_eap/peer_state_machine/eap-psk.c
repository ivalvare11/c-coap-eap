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

#include <string.h>

#include "eap-psk.h"
#include "include.h"
#include "own-aes.h"

static uint8_t psk[16] = {0x06, 0xb4, 0xbe, 0x19, 0xda, 0x28, 0x9f, 0x47, 0x5a, 0xa4, 0x6a, 0x33, 0xcb, 0x79, 0x30, 0x29};

#define reqId ((struct eap_msg *)eapReqData)->id
#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqCode ((struct eap_msg *)eapReqData)->code
#define reqLength ((struct eap_msg *)eapReqData)->length

unsigned char tek_key[16];
unsigned char ak[16];
unsigned char kdk[16];
uint8_t step;
unsigned char rand_s[16];
unsigned char rand_p[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
unsigned char id_s[16];
unsigned short id_s_length;
unsigned char ct[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

unsigned char nonce[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

unsigned char data_ciphered[16];
unsigned char tag_bug[16];
unsigned char header[22];
unsigned char msg[1] = {0x80};

unsigned char output [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Auxiliar AES register
uint8_t it;
uint16_t aux;
static uint8_t data [64];

// * For key derivation in Peer
int psk_key_available;
uint8_t msk_key[MSK_LENGTH];

void initMethodEap_psk()
{		
	// AesCtx ctx; //Aes context
	//	aes_context ctx;


	// Init variables
	psk_key_available = FALSE; //In the beginning there is no key
	step = 0; //In the beginning there is no eap-psk message

	//Init psk with the password configured in ../include.h
	//memcpy(psk, PASSWORD, sizeof(PASSWORD));

	//Init the Aes ctx with the psk
	//AesCtxIni(&ctx, NULL, psk, KEY128, CBC);
	//cc2420_aes_set_key(psk, 0);
	//aes_set_key(psk, 16, &ctx);
	//printf("PSK\n");
	//printf_hex(psk,16);	
	//aes_set_key(psk, 16, &ctx);

	//Init the rand_p
	for (it=0; it<16; it=it+2){
		aux = random_rand();
		memcpy(rand_p+it, &aux, sizeof(unsigned short)); //2 uint8_ts
	}
	
	///////AK and KDK derivation

	//Init constant as ct0
	memset(ct, 0, sizeof(ct));

	//	printf("AK CREATION--\n");
	//	printf_hex(ct,16);
	/////AES-128(PSK,ct0)
	//bACI_ECBencodeStripe(psk, TRUE, ct, output);
	//AesEncrypt(&ctx, ct, output, sizeof(ct));
	//cc2420_aes_cipher(ct, 16, 0);
	memcpy(output, ct, 16);
	//	aesencrypt(ct, output, &ctx);
	aes_encrypt(output,psk);

	//printf_hex(output,16);

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	/////XOR (ct1, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}
	//printf_hex(ct,16);

	////AK = AES-128(PSK, XOR (ct1, AES-128(PSK, ct0)))
	//bACI_ECBencodeStripe(psk, TRUE, ct, ak); //The psk is not set because it is just set
	//AesEncrypt(&ctx, ct, ak, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(ak, ct, sizeof(ct));
	
	//	aesencrypt(ct, ak, &ctx);
	aes_encrypt(ak,psk);
	//printf_hex(ak,16);

	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	/////XOR (ct2, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	////KDK = AES-128 (PSK, XOR (ct2, AES-128(PSK, ct0)) )
	//bACI_ECBencodeStripe(psk, TRUE, ct, kdk); //The psk is not set because it is just set
	//AesEncrypt(&ctx, ct, kdk, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(kdk, ct, sizeof(ct));
	memcpy(kdk,ct,sizeof(ct));
	//	aesencrypt(ct, kdk, &ctx);
	aes_encrypt(kdk,psk);

	///Generating tek, msk and emsk
	//AES-128(KDK, RAND_P)
	//bACI_ECBencodeStripe(kdk, TRUE, rand_p, output);
	//cc2420_aes_set_key(kdk, 0);
	//	aes_set_key(kdk, 16, &ctx);

	//AesCtxIni(&ctx, NULL, kdk, KEY128, CBC);
	//AesEncrypt(&ctx, rand_p, output, sizeof(rand_p));
	//cc2420_aes_cipher(rand_p, sizeof(rand_p), 0);
	//memcpy(output, rand_p, sizeof(rand_p));
	memcpy(output,rand_p, sizeof(rand_p));
	//	aesencrypt(rand_p, output, &ctx);
	aes_encrypt(output,kdk);	

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	//XOR (ct1, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//TEK = AES-128(KDK, XOR (ct1, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, tek_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, tek_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(tek_key, ct, sizeof(ct));
	//aesencrypt(ct, tek_key, &ctx);
	aes_encrypt(tek_key,kdk);
	
	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	//XOR (ct2, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//MSK 1/4 = AES-128(KDK, XOR (ct2, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(msk_key, ct, sizeof(ct));
	//	aesencrypt(ct, msk_key, &ctx);
	aes_encrypt(msk_key,kdk);

	//Init constant as ct3
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x03;
	
	//XOR (ct3, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++)
		ct[it] = ct[it]^output[it];

	//MSK 2/4 = AES-128(KDK, XOR (ct3, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+16); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+16, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(msk_key+16, ct, sizeof(ct));
	aes_encrypt(msk_key+16, kdk);

	//Init constant as ct4
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x04;
	
	//XOR (ct4, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++)
		ct[it] = ct[it]^output[it];

	//MSK 3/4 = AES-128(KDK, XOR (ct4, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+32); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+32, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(msk_key+32, ct, sizeof(ct));
	aes_encrypt(msk_key+32, kdk);

	//Init constant as ct5
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x05;
	
	//XOR (ct5, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++)
		ct[it] = ct[it]^output[it];

	//MSK 4/4 = AES-128(KDK, XOR (ct5, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+48); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+48, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	memcpy(msk_key+48, ct, sizeof(ct));	
	aes_encrypt(msk_key+48, kdk);

	//Init constant as ct6 
	/*	memset(ct, 0, sizeof(ct));
	ct[15] = 0x06;
	
	//XOR (ct6, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 1/4 = AES-128(KDK, XOR (ct6, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key, ct, sizeof(ct));	
	aesencrypt(ct, emsk_key, &ctx);

	//Init constant as ct7
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x07;
	
	//XOR (ct7, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 2/4 = AES-128(KDK, XOR (ct7, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+16); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+16, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+16, ct, sizeof(ct));	
	aesencrypt(ct, emsk_key+16, &ctx);

	//Init constant as ct8
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x08;
	
	//XOR (ct8, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 3/4 = AES-128(KDK, XOR (ct8, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+32); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+32, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+32, ct, sizeof(ct));		
	aesencrypt(ct, emsk_key+32, &ctx);

	//Init constant as ct9
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x09;
	
	//XOR (ct9, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 4/4 = AES-128(KDK, XOR (ct9, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+48); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+48, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+48, ct, sizeof(ct));
	aesencrypt(ct, emsk_key+48, &ctx);  */
}

uint8_t check_psk(const uint8_t * eapReqData)
{
	if (reqMethod == EAP_PSK)
		return TRUE;

	return FALSE;
}

// Process the EAP-PSK Request message. The results are obtained in the
// methodState and decision variables.
void process_psk(const uint8_t * eapReqData, uint8_t * methodState, uint8_t * decision){
	if (reqMethod==EAP_PSK && reqCode==REQUEST_CODE ){ //Type EAP-PSK && Code=1
		step++;
		
		//if (step==1){ //EAP-PSK first message
		if (eapReqData[5]==0x00){ //EAP-PSK first message
			step=2; //The next step is EAP-PSK 2
			memcpy(rand_s, eapReqData+6, 16);
			
			id_s_length = NTOHS(reqLength) -22;
			
			memcpy(id_s, eapReqData+22, id_s_length);

			
			*(methodState)= MAY_CONT;
			*(decision)=COND_SUCC;

		}
		//else if (step==3){ //EAP-PSK third message
		else if (eapReqData[5]==0x80){ //EAP-PSK third message
			step=4; //The next step is EAP-PSK 2
			//Checking rand_s
			
			for (it=0; it<16; it++) {
				if (eapReqData[6+it] != rand_s [it]){
					*(methodState)= MAY_CONT;
					*(decision)=FAIL;
					return;
				}
			}

			//checking MAC_S = CMAC-AES-128 (AK, ID_S||RAND_P)
			memcpy(data, id_s, id_s_length);
			memcpy(data+id_s_length, rand_p, 16);


			//AES_CMAC ( (char *) &ak, data, 32,
            //      mac_s );

            do_omac(ak, data, id_s_length+16, output); //output == mac_s

			// printf("EAP-PSK: MAC-S\n");
			// printf_hex(output, 16);

			for (it=0; it<16; it++){
				if (eapReqData[22+it] != output[it]){ //output == mac_s
					*(methodState)= MAY_CONT;
					*(decision)=FAIL;
					return;
				}
			}
			
			*(methodState)= MAY_CONT;
			*(decision)=COND_SUCC;
			psk_key_available=TRUE;
			eapKeyAvailable = TRUE;
		}	
	}
}

// void printf_hex(unsigned char*, int);
// void printf_hex(unsigned char* text, int length)
// {
//     int i;
//     for (i = 0; i < length; i++)
//         printf("%02x", text[i]);
//     printf("\n");
//     return;
// }

//Build the EAP-PSK Response message depending on the step variable value
void buildResp_psk(uint8_t * eapRespData, const uint8_t identifier){
	//step++; //Step is set in process function
	//Building EAP-PSK message
	
	if (step==2){ //EAP-PSK second message
		((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
		((struct eap_msg *)eapRespData)->id = identifier;
		((struct eap_msg *)eapRespData)->length = HTONS(54+ID_P_LENGTH);
		((struct eap_msg *)eapRespData)->method = EAP_PSK;
		eapRespData[5] = 0x40; //T=1 in flags field
		/*		
		printf("EAP-PSK: AK\n");
		printf_hex(ak, 16);

		printf("EAP-PSK: ID_P\n");
		printf_hex("client", 6);
		
		printf("EAP-PSK: ID_S\n");
		printf_hex(id_s, id_s_length);

		printf("EAP-PSK: RAND_S\n");
		printf_hex(rand_s, 16);

		printf("EAP-PSK: RAND_P\n");
		printf_hex(rand_p, 16);
		*/

		memcpy((eapRespData+6), rand_s, 16);
		memcpy((eapRespData+22), rand_p, 16);

		//Calculating MAC_P = CMAC-AES-128(AK, ID_P||ID_S||RAND_S||RAND_P)
		//memcpy(data, id_p, ID_P_LENGTH);
		memcpy(data, "client", strlen("client"));

		memcpy(data+ID_P_LENGTH, id_s, id_s_length);
		memcpy(data+ID_P_LENGTH+id_s_length, rand_s, 16);
		memcpy(data+ID_P_LENGTH+id_s_length+16, rand_p, 16);

		//	printf("EAP-PSK: CMAC-AES-128(AK, ID_P||ID_S||RAND_S||RAND_P)\n");
		//	printf_hex(data, ID_P_LENGTH+id_s_length+16+16);

       	do_omac(ak, data, ID_P_LENGTH+id_s_length+16+16, output); //output == mac_p

		// printf("EAP-PSK: MAC-P\n");
		// printf_hex(output, 16);		
	
		memcpy(eapRespData+38, output, 16); //output == mac_p
		//memcpy(eapRespData+54, id_p, ID_P_LENGTH);
		memcpy(eapRespData+54, "client", strlen("client"));

	}
	else if (step==4){ //EAP-PSK fourth message
		((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
		((struct eap_msg *)eapRespData)->id = identifier;
		((struct eap_msg *)eapRespData)->length = HTONS(43);
		((struct eap_msg *)eapRespData)->method = EAP_PSK;
		eapRespData[5] = 0xc0; //T=3 Flags

		memcpy(eapRespData+6, rand_s, 16);
		memcpy(eapRespData+22, nonce+12, 4); //Only the last four digits are used.

		//Set the values to calculate the tag
		memcpy(header, eapRespData, 22);
		do_eax(tek_key, nonce,
		msg, 1,
		header, 22,
		data_ciphered,
		tag_bug, 16);

		memcpy(eapRespData+26, tag_bug, 16);
		memcpy(eapRespData+42, data_ciphered, 1);

		psk_key_available = TRUE;
		eapKeyAvailable = TRUE;
	} 
	
}

// Return the MSK key
uint8_t * getKey()
{
	return (uint8_t *)msk_key;
}

// Return TRUE if the MSK is available. FALSE otherwise.
uint8_t isKeyAvailable()
{
	return psk_key_available;
}