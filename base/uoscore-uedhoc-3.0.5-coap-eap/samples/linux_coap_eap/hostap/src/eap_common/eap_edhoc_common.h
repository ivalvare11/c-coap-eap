

#ifndef EAP_EDHOC_COMMON_H
#define EAP_EDHOC_COMMON_H

//Defining EDHOC flags:

/*   Flags

     0 1 2 3 4 5 6 7 8
     +-+-+-+-+-+-+-+-+
     |L M S V R R R R|
     +-+-+-+-+-+-+-+-+
*/

#define EDHOC_L_FLAG		128
#define EDHOC_M_FLAG		64
#define EDHOC_S_FLAG		32
//Reverse Role flag.
#define EDHOC_V_FLAG		16

// 0: direct role scheme.
// 1: reverse role scheme.
#define ROLE_SCHEME 0

#define MAX_FRAGMENT_SIZE 2000

//T1_RFC9529: Using RFC9529 test vectors.
//ORIG: Using p256_v16 test vectors.
#define ORIG

//This variable is only used when ORIG is defined --> There are several p256_v16 test vectors, choose one (select 5 or 6 for method 3, select 7 for PSK auth).
#define TEST_VECTORS_NUM 6

//Uncomment this line to activate the PSK derivation after successful authentications: 
//#define RESUMPTION

// Comment this line to disable time measurement.
#define MEASURE_TIME

//0: No debug prints.
//1: Debug prints.
#define DEBUG_INFO 0

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

void eap_edhoc_peer_cred_gen(struct cred_array *cred_r_array, struct edhoc_initiator_context *c_i);
void eap_edhoc_server_cred_gen(struct cred_array *cred_i_array, struct edhoc_responder_context *c_r);

void fragment_buffer_init(fragment_buffer_t *buffer, size_t len);
void fragment_buffer_free(fragment_buffer_t *buffer);
void fragment_buffer_append_recv(fragment_buffer_t *buffer, const uint8_t *data, size_t len);
int more_fragments_needed(const fragment_buffer_t *buffer);
int get_next_fragment(fragment_buffer_t *buffer, uint8_t *fragment, size_t *fragment_len);


#endif /* EAP_EDHOC_COMMON_H */
