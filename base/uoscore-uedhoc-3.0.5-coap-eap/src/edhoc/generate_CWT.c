
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "edhoc.h"
#include "cbor/cwt_encode.h"
#include "common/oscore_edhoc_error.h"

enum err generate_CWT_cred(char *issuer_str, struct byte_array *KID, struct byte_array *PSK, struct byte_array *cred){
 	struct CWT cwt;
   memset(&cwt, 0, sizeof(cwt));

   // Set issuer string
   cwt.CWT_uint2tstr.value = (const uint8_t *)issuer_str;
   cwt.CWT_uint2tstr.len = sizeof(issuer_str) + 1;
   
   // kty (symmetric)
   cwt.CWT_Claim_Key_m.Claim_Key_COSE_Key_m.COSE_Key_uint1int = 4;

   // kid
   cwt.CWT_Claim_Key_m.Claim_Key_COSE_Key_m.COSE_Key_uint2bstr.value = KID->ptr;
   cwt.CWT_Claim_Key_m.Claim_Key_COSE_Key_m.COSE_Key_uint2bstr.len = KID->len;

   // key (k)
   cwt.CWT_Claim_Key_m.Claim_Key_COSE_Key_m.COSE_Key_nintbstr.value = PSK->ptr;
   cwt.CWT_Claim_Key_m.Claim_Key_COSE_Key_m.COSE_Key_nintbstr.len = PSK->len;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_CWT(cred->ptr, cred->len, &cwt,
					 &payload_len_out),
		   0);
	cred->len = (uint32_t)payload_len_out;

   return ok;
}