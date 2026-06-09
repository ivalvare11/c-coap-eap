/*
 * EAP server/peer: EAP-PSK shared routines
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_PSK_COMMON_H
#define EAP_PSK_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define EAP_PSK_RAND_LEN 16
#define EAP_PSK_MAC_LEN 16
#define EAP_PSK_TEK_LEN 16
#define EAP_PSK_PSK_LEN 16
#define EAP_PSK_AK_LEN 16
#define EAP_PSK_KDK_LEN 16

#define EAP_PSK_R_FLAG_CONT 1
#define EAP_PSK_R_FLAG_DONE_SUCCESS 2
#define EAP_PSK_R_FLAG_DONE_FAILURE 3
#define EAP_PSK_E_FLAG 0x20

#define EAP_PSK_FLAGS_GET_T(flags) (((flags) & 0xc0) >> 6)
#define EAP_PSK_FLAGS_SET_T(t) ((uint8_t) (t) << 6)

#define EAP_MSK_LEN 64
#define EAP_EMSK_LEN 64

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

/* EAP-PSK First Message (AS -> Supplicant) */
struct eap_psk_hdr_1 {
	uint8_t flags;
	uint8_t rand_s[EAP_PSK_RAND_LEN];
	/* Followed by variable length ID_S */
} __attribute__ ((packed));

/* EAP-PSK Second Message (Supplicant -> AS) */
struct eap_psk_hdr_2 {
	uint8_t flags;
	uint8_t rand_s[EAP_PSK_RAND_LEN];
	uint8_t rand_p[EAP_PSK_RAND_LEN];
	uint8_t mac_p[EAP_PSK_MAC_LEN];
	/* Followed by variable length ID_P */
} __attribute__ ((packed));

/* EAP-PSK Third Message (AS -> Supplicant) */
struct eap_psk_hdr_3 {
	uint8_t flags;
	uint8_t rand_s[EAP_PSK_RAND_LEN];
	uint8_t mac_s[EAP_PSK_MAC_LEN];
	/* Followed by variable length PCHANNEL */
} __attribute__ ((packed));

/* EAP-PSK Fourth Message (Supplicant -> AS) */
struct eap_psk_hdr_4 {
	uint8_t flags;
	uint8_t rand_s[EAP_PSK_RAND_LEN];
	/* Followed by variable length PCHANNEL */
} __attribute__ ((packed));



#endif /* EAP_PSK_COMMON_H */
