#ifndef PSK_API_H
#define PSK_API_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "edhoc.h"
#include "edhoc/runtime_context.h"

#include "common/oscore_edhoc_error.h"

enum err store_creds(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r, const char *filename);

enum err get_last_creds(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r, const char *filename);

enum err set_resp_creds_file(char *filename);

enum err get_creds_by_id(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r);
#endif
