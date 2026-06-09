#ifndef _EAP_EDHOC_H
#define _EAP_EDHOC_H

RCSIDH(eap_edhoc_h, "$Id$")

#include "eap.h"
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "edhoc.h"
#include "edhoc_internal.h"
#include "psk_api.h"

//Defining EDHOC flags:

/*   Flags

     0 1 2 3 4 5 6 7 8
     +-+-+-+-+-+-+-+-+
     |L M S V R R R R|
     +-+-+-+-+-+-+-+-+
*/

#define PW_EDHOC_L_FLAG		128
#define PW_EDHOC_M_FLAG		64
#define PW_EDHOC_S_FLAG		32
//Reverse Role flag.
#define PW_EDHOC_V_FLAG		16

// 0: direct role scheme.
// 1: reverse role scheme.
#define ROLE_SCHEME 0

#define MAX_FRAGMENT_SIZE 2000

//T1_RFC9529: Using RFC9529 test vectors.
//ORIG: Using p256_v16 test vectors.
#define ORIG

//This variable is only used when ORIG is defined --> There are several p256_v16 test vectors, choose one (select 5 or 6 for method 3, select 7 for PSK auth).
// 1 -> 0 
// 5 -> 3
// 7 -> 4
#define TEST_VECTORS_NUM 1

//Uncomment this line to activate the PSK derivation after successful authentications: 
//#define RESUMPTION

// Comment this line to disable time measurement.
// #define MEASURE_TIME

// 0: No debug prints.
// 1: Debug prints.
#define DEBUG_INFO 1

#if DEBUG_INFO
    #define DEBUG_MSG(fmt, ...) do { \
        if (*#fmt != '\0') { \
            printf(fmt "\n", ##__VA_ARGS__); \
        } else { \
            printf("\n"); \
        } \
    } while (0)
    #define DEBUG_PRINT_ARRAY(array, len) print_array(array, len);
#else
    #define DEBUG_MSG(fmt, ...) // Do nothing
    #define DEBUG_PRINT_ARRAY(array, len) // Do nothing
#endif

//Fragmentation buffer.
typedef struct fragment_buffer_t{
	uint8_t *data;
	size_t len;
	size_t offset;
} fragment_buffer_t;


typedef struct rlm_eap_edhoc_t {
	enum { START, MSG1_recv, MSG2_send, MSG3_recv, MSG4_send, SUCCESS, FAILURE } state;
	
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array PRK_exporter;
	struct byte_array err_msg;
	
	struct byte_array c_i;
	
	struct edhoc_responder_context c_r;
	struct cred_array cred_i_array;
	struct runtime_context rc;
	struct fragment_buffer_t frag_buffer;
} rlm_eap_edhoc_t;

typedef struct rlm_eap_edhoc_t_rev {
	enum { MSG1_send, MSG2_recv, MSG3_send, SUCCESS_I, FAILURE_I } state;
	
	struct byte_array msk;
	struct byte_array emsk;
	struct byte_array method_id;
	struct byte_array PRK_out;
	struct byte_array PRK_exporter;
	struct byte_array err_msg;
	
	struct byte_array c_r;
	struct edhoc_initiator_context c_i;
	struct cred_array cred_r_array;
	struct runtime_context rc;
	struct fragment_buffer_t frag_buffer;
} rlm_eap_edhoc_t_rev;


#endif /*_EAP_EDHOC_H*/
