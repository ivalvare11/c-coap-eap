/*
 * rlm_eap_psk.c    Handles that are called from eap
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2001,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

RCSID("$Id$")

#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "eax.h"

#include "eap_psk.h"
#include "eap_psk_common.h"

#include <freeradius-devel/rad_assert.h>


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

/* functions for finite field multiplication in the AES Galois field    */

#define WPOLY   0x011b
#define BPOLY     0x1b
#define DPOLY   0x008d

#define f1(x)   (x)
#define f2(x)   ((x << 1) ^ (((x >> 7) & 1) * WPOLY))
#define f4(x)   ((x << 2) ^ (((x >> 6) & 1) * WPOLY) ^ (((x >> 6) & 2) * WPOLY))
#define f8(x)   ((x << 3) ^ (((x >> 5) & 1) * WPOLY) ^ (((x >> 5) & 2) * WPOLY) \
                          ^ (((x >> 5) & 4) * WPOLY))
#define d2(x)   (((x) >> 1) ^ ((x) & 1 ? DPOLY : 0))

#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

#if defined( USE_TABLES )

#define sb_data(w) {    /* S Box data values */                            \
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define isb_data(w) {   /* inverse S Box data values */                    \
    w(0x52), w(0x09), w(0x6a), w(0xd5), w(0x30), w(0x36), w(0xa5), w(0x38),\
    w(0xbf), w(0x40), w(0xa3), w(0x9e), w(0x81), w(0xf3), w(0xd7), w(0xfb),\
    w(0x7c), w(0xe3), w(0x39), w(0x82), w(0x9b), w(0x2f), w(0xff), w(0x87),\
    w(0x34), w(0x8e), w(0x43), w(0x44), w(0xc4), w(0xde), w(0xe9), w(0xcb),\
    w(0x54), w(0x7b), w(0x94), w(0x32), w(0xa6), w(0xc2), w(0x23), w(0x3d),\
    w(0xee), w(0x4c), w(0x95), w(0x0b), w(0x42), w(0xfa), w(0xc3), w(0x4e),\
    w(0x08), w(0x2e), w(0xa1), w(0x66), w(0x28), w(0xd9), w(0x24), w(0xb2),\
    w(0x76), w(0x5b), w(0xa2), w(0x49), w(0x6d), w(0x8b), w(0xd1), w(0x25),\
    w(0x72), w(0xf8), w(0xf6), w(0x64), w(0x86), w(0x68), w(0x98), w(0x16),\
    w(0xd4), w(0xa4), w(0x5c), w(0xcc), w(0x5d), w(0x65), w(0xb6), w(0x92),\
    w(0x6c), w(0x70), w(0x48), w(0x50), w(0xfd), w(0xed), w(0xb9), w(0xda),\
    w(0x5e), w(0x15), w(0x46), w(0x57), w(0xa7), w(0x8d), w(0x9d), w(0x84),\
    w(0x90), w(0xd8), w(0xab), w(0x00), w(0x8c), w(0xbc), w(0xd3), w(0x0a),\
    w(0xf7), w(0xe4), w(0x58), w(0x05), w(0xb8), w(0xb3), w(0x45), w(0x06),\
    w(0xd0), w(0x2c), w(0x1e), w(0x8f), w(0xca), w(0x3f), w(0x0f), w(0x02),\
    w(0xc1), w(0xaf), w(0xbd), w(0x03), w(0x01), w(0x13), w(0x8a), w(0x6b),\
    w(0x3a), w(0x91), w(0x11), w(0x41), w(0x4f), w(0x67), w(0xdc), w(0xea),\
    w(0x97), w(0xf2), w(0xcf), w(0xce), w(0xf0), w(0xb4), w(0xe6), w(0x73),\
    w(0x96), w(0xac), w(0x74), w(0x22), w(0xe7), w(0xad), w(0x35), w(0x85),\
    w(0xe2), w(0xf9), w(0x37), w(0xe8), w(0x1c), w(0x75), w(0xdf), w(0x6e),\
    w(0x47), w(0xf1), w(0x1a), w(0x71), w(0x1d), w(0x29), w(0xc5), w(0x89),\
    w(0x6f), w(0xb7), w(0x62), w(0x0e), w(0xaa), w(0x18), w(0xbe), w(0x1b),\
    w(0xfc), w(0x56), w(0x3e), w(0x4b), w(0xc6), w(0xd2), w(0x79), w(0x20),\
    w(0x9a), w(0xdb), w(0xc0), w(0xfe), w(0x78), w(0xcd), w(0x5a), w(0xf4),\
    w(0x1f), w(0xdd), w(0xa8), w(0x33), w(0x88), w(0x07), w(0xc7), w(0x31),\
    w(0xb1), w(0x12), w(0x10), w(0x59), w(0x27), w(0x80), w(0xec), w(0x5f),\
    w(0x60), w(0x51), w(0x7f), w(0xa9), w(0x19), w(0xb5), w(0x4a), w(0x0d),\
    w(0x2d), w(0xe5), w(0x7a), w(0x9f), w(0x93), w(0xc9), w(0x9c), w(0xef),\
    w(0xa0), w(0xe0), w(0x3b), w(0x4d), w(0xae), w(0x2a), w(0xf5), w(0xb0),\
    w(0xc8), w(0xeb), w(0xbb), w(0x3c), w(0x83), w(0x53), w(0x99), w(0x61),\
    w(0x17), w(0x2b), w(0x04), w(0x7e), w(0xba), w(0x77), w(0xd6), w(0x26),\
    w(0xe1), w(0x69), w(0x14), w(0x63), w(0x55), w(0x21), w(0x0c), w(0x7d) }

#define mm_data(w) {    /* basic data for forming finite field tables */   \
    w(0x00), w(0x01), w(0x02), w(0x03), w(0x04), w(0x05), w(0x06), w(0x07),\
    w(0x08), w(0x09), w(0x0a), w(0x0b), w(0x0c), w(0x0d), w(0x0e), w(0x0f),\
    w(0x10), w(0x11), w(0x12), w(0x13), w(0x14), w(0x15), w(0x16), w(0x17),\
    w(0x18), w(0x19), w(0x1a), w(0x1b), w(0x1c), w(0x1d), w(0x1e), w(0x1f),\
    w(0x20), w(0x21), w(0x22), w(0x23), w(0x24), w(0x25), w(0x26), w(0x27),\
    w(0x28), w(0x29), w(0x2a), w(0x2b), w(0x2c), w(0x2d), w(0x2e), w(0x2f),\
    w(0x30), w(0x31), w(0x32), w(0x33), w(0x34), w(0x35), w(0x36), w(0x37),\
    w(0x38), w(0x39), w(0x3a), w(0x3b), w(0x3c), w(0x3d), w(0x3e), w(0x3f),\
    w(0x40), w(0x41), w(0x42), w(0x43), w(0x44), w(0x45), w(0x46), w(0x47),\
    w(0x48), w(0x49), w(0x4a), w(0x4b), w(0x4c), w(0x4d), w(0x4e), w(0x4f),\
    w(0x50), w(0x51), w(0x52), w(0x53), w(0x54), w(0x55), w(0x56), w(0x57),\
    w(0x58), w(0x59), w(0x5a), w(0x5b), w(0x5c), w(0x5d), w(0x5e), w(0x5f),\
    w(0x60), w(0x61), w(0x62), w(0x63), w(0x64), w(0x65), w(0x66), w(0x67),\
    w(0x68), w(0x69), w(0x6a), w(0x6b), w(0x6c), w(0x6d), w(0x6e), w(0x6f),\
    w(0x70), w(0x71), w(0x72), w(0x73), w(0x74), w(0x75), w(0x76), w(0x77),\
    w(0x78), w(0x79), w(0x7a), w(0x7b), w(0x7c), w(0x7d), w(0x7e), w(0x7f),\
    w(0x80), w(0x81), w(0x82), w(0x83), w(0x84), w(0x85), w(0x86), w(0x87),\
    w(0x88), w(0x89), w(0x8a), w(0x8b), w(0x8c), w(0x8d), w(0x8e), w(0x8f),\
    w(0x90), w(0x91), w(0x92), w(0x93), w(0x94), w(0x95), w(0x96), w(0x97),\
    w(0x98), w(0x99), w(0x9a), w(0x9b), w(0x9c), w(0x9d), w(0x9e), w(0x9f),\
    w(0xa0), w(0xa1), w(0xa2), w(0xa3), w(0xa4), w(0xa5), w(0xa6), w(0xa7),\
    w(0xa8), w(0xa9), w(0xaa), w(0xab), w(0xac), w(0xad), w(0xae), w(0xaf),\
    w(0xb0), w(0xb1), w(0xb2), w(0xb3), w(0xb4), w(0xb5), w(0xb6), w(0xb7),\
    w(0xb8), w(0xb9), w(0xba), w(0xbb), w(0xbc), w(0xbd), w(0xbe), w(0xbf),\
    w(0xc0), w(0xc1), w(0xc2), w(0xc3), w(0xc4), w(0xc5), w(0xc6), w(0xc7),\
    w(0xc8), w(0xc9), w(0xca), w(0xcb), w(0xcc), w(0xcd), w(0xce), w(0xcf),\
    w(0xd0), w(0xd1), w(0xd2), w(0xd3), w(0xd4), w(0xd5), w(0xd6), w(0xd7),\
    w(0xd8), w(0xd9), w(0xda), w(0xdb), w(0xdc), w(0xdd), w(0xde), w(0xdf),\
    w(0xe0), w(0xe1), w(0xe2), w(0xe3), w(0xe4), w(0xe5), w(0xe6), w(0xe7),\
    w(0xe8), w(0xe9), w(0xea), w(0xeb), w(0xec), w(0xed), w(0xee), w(0xef),\
    w(0xf0), w(0xf1), w(0xf2), w(0xf3), w(0xf4), w(0xf5), w(0xf6), w(0xf7),\
    w(0xf8), w(0xf9), w(0xfa), w(0xfb), w(0xfc), w(0xfd), w(0xfe), w(0xff) }

static const uint8_t sbox[256]  =  sb_data(f1);
static const uint8_t isbox[256] = isb_data(f1);

static const uint8_t gfm2_sbox[256] = sb_data(f2);
static const uint8_t gfm3_sbox[256] = sb_data(f3);

static const uint8_t gfmul_9[256] = mm_data(f9);
static const uint8_t gfmul_b[256] = mm_data(fb);
static const uint8_t gfmul_d[256] = mm_data(fd);
static const uint8_t gfmul_e[256] = mm_data(fe);

#define s_box(x)     sbox[(x)]
#define is_box(x)    isbox[(x)]
#define gfm2_sb(x)   gfm2_sbox[(x)]
#define gfm3_sb(x)   gfm3_sbox[(x)]
#define gfm_9(x)     gfmul_9[(x)]
#define gfm_b(x)     gfmul_b[(x)]
#define gfm_d(x)     gfmul_d[(x)]
#define gfm_e(x)     gfmul_e[(x)]

#else

/* this is the high bit of x right shifted by 1 */
/* position. Since the starting polynomial has  */
/* 9 bits (0x11b), this right shift keeps the   */
/* values of all top bits within a byte         */

static uint8_t hibit(const uint8_t x)
{   uint8_t r = (uint8_t)((x >> 1) | (x >> 2));

    r |= (r >> 2);
    r |= (r >> 4);
    return (r + 1) >> 1;
}

/* return the inverse of the finite field element x */

static uint8_t gf_inv(const uint8_t x)
{   uint8_t p1 = x, p2 = BPOLY, n1 = hibit(x), n2 = 0x80, v1 = 1, v2 = 0;

    if(x < 2) 
        return x;

    for( ; ; )
    {
        if(n1)
            while(n2 >= n1)             /* divide polynomial p2 by p1    */
            {
                n2 /= n1;               /* shift smaller polynomial left */ 
                p2 ^= (p1 * n2) & 0xff; /* and remove from larger one    */
                v2 ^= (v1 * n2);        /* shift accumulated value and   */ 
                n2 = hibit(p2);         /* add into result               */
            }
        else
            return v1;

        if(n2)                          /* repeat with values swapped    */ 
            while(n1 >= n2)
            {
                n1 /= n2; 
                p1 ^= p2 * n1; 
                v1 ^= v2 * n1; 
                n1 = hibit(p1);
            }
        else
            return v2;
    }
}

/* The forward and inverse affine transformations used in the S-box */
static uint8_t fwd_affine(const uint8_t x)
{   
#if defined( HAVE_UINT_32T )
    uint_32t w = x;
    w ^= (w << 1) ^ (w << 2) ^ (w << 3) ^ (w << 4);
    return 0x63 ^ ((w ^ (w >> 8)) & 0xff);
#else
    return 0x63 ^ x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) 
                    ^ (x >> 7) ^ (x >> 6) ^ (x >> 5) ^ (x >> 4);
#endif
}

static uint8_t inv_affine(const uint8_t x)
{
#if defined( HAVE_UINT_32T )
    uint_32t w = x;
    w = (w << 1) ^ (w << 3) ^ (w << 6);
    return 0x05 ^ ((w ^ (w >> 8)) & 0xff);
#else
    return 0x05 ^ (x << 1) ^ (x << 3) ^ (x << 6) 
                ^ (x >> 7) ^ (x >> 5) ^ (x >> 2);
#endif
}

#define s_box(x)   fwd_affine(gf_inv(x))
#define is_box(x)  gf_inv(inv_affine(x))
#define gfm2_sb(x) f2(s_box(x))
#define gfm3_sb(x) f3(s_box(x))
#define gfm_9(x)   f9(x)
#define gfm_b(x)   fb(x)
#define gfm_d(x)   fd(x)
#define gfm_e(x)   fe(x)

#endif

#define block_copy_nn(d, s, l)    memcpy(d, s, l)
#define block_copy(d, s)          memcpy(d, s, N_BLOCK)



static void xor_block( void *d, const void *s )
{
#if defined( HAVE_UINT_32T )
    ((uint_32t*)d)[ 0] ^= ((uint_32t*)s)[ 0];
    ((uint_32t*)d)[ 1] ^= ((uint_32t*)s)[ 1];
    ((uint_32t*)d)[ 2] ^= ((uint_32t*)s)[ 2];
    ((uint_32t*)d)[ 3] ^= ((uint_32t*)s)[ 3];
#else
    ((uint8_t*)d)[ 0] ^= ((uint8_t*)s)[ 0];
    ((uint8_t*)d)[ 1] ^= ((uint8_t*)s)[ 1];
    ((uint8_t*)d)[ 2] ^= ((uint8_t*)s)[ 2];
    ((uint8_t*)d)[ 3] ^= ((uint8_t*)s)[ 3];
    ((uint8_t*)d)[ 4] ^= ((uint8_t*)s)[ 4];
    ((uint8_t*)d)[ 5] ^= ((uint8_t*)s)[ 5];
    ((uint8_t*)d)[ 6] ^= ((uint8_t*)s)[ 6];
    ((uint8_t*)d)[ 7] ^= ((uint8_t*)s)[ 7];
    ((uint8_t*)d)[ 8] ^= ((uint8_t*)s)[ 8];
    ((uint8_t*)d)[ 9] ^= ((uint8_t*)s)[ 9];
    ((uint8_t*)d)[10] ^= ((uint8_t*)s)[10];
    ((uint8_t*)d)[11] ^= ((uint8_t*)s)[11];
    ((uint8_t*)d)[12] ^= ((uint8_t*)s)[12];
    ((uint8_t*)d)[13] ^= ((uint8_t*)s)[13];
    ((uint8_t*)d)[14] ^= ((uint8_t*)s)[14];
    ((uint8_t*)d)[15] ^= ((uint8_t*)s)[15];
#endif
}

static void copy_and_key( void *d, const void *s, const void *k )
{
#if defined( HAVE_UINT_32T )
    ((uint_32t*)d)[ 0] = ((uint_32t*)s)[ 0] ^ ((uint_32t*)k)[ 0];
    ((uint_32t*)d)[ 1] = ((uint_32t*)s)[ 1] ^ ((uint_32t*)k)[ 1];
    ((uint_32t*)d)[ 2] = ((uint_32t*)s)[ 2] ^ ((uint_32t*)k)[ 2];
    ((uint_32t*)d)[ 3] = ((uint_32t*)s)[ 3] ^ ((uint_32t*)k)[ 3];
#elif 1
    ((uint8_t*)d)[ 0] = ((uint8_t*)s)[ 0] ^ ((uint8_t*)k)[ 0];
    ((uint8_t*)d)[ 1] = ((uint8_t*)s)[ 1] ^ ((uint8_t*)k)[ 1];
    ((uint8_t*)d)[ 2] = ((uint8_t*)s)[ 2] ^ ((uint8_t*)k)[ 2];
    ((uint8_t*)d)[ 3] = ((uint8_t*)s)[ 3] ^ ((uint8_t*)k)[ 3];
    ((uint8_t*)d)[ 4] = ((uint8_t*)s)[ 4] ^ ((uint8_t*)k)[ 4];
    ((uint8_t*)d)[ 5] = ((uint8_t*)s)[ 5] ^ ((uint8_t*)k)[ 5];
    ((uint8_t*)d)[ 6] = ((uint8_t*)s)[ 6] ^ ((uint8_t*)k)[ 6];
    ((uint8_t*)d)[ 7] = ((uint8_t*)s)[ 7] ^ ((uint8_t*)k)[ 7];
    ((uint8_t*)d)[ 8] = ((uint8_t*)s)[ 8] ^ ((uint8_t*)k)[ 8];
    ((uint8_t*)d)[ 9] = ((uint8_t*)s)[ 9] ^ ((uint8_t*)k)[ 9];
    ((uint8_t*)d)[10] = ((uint8_t*)s)[10] ^ ((uint8_t*)k)[10];
    ((uint8_t*)d)[11] = ((uint8_t*)s)[11] ^ ((uint8_t*)k)[11];
    ((uint8_t*)d)[12] = ((uint8_t*)s)[12] ^ ((uint8_t*)k)[12];
    ((uint8_t*)d)[13] = ((uint8_t*)s)[13] ^ ((uint8_t*)k)[13];
    ((uint8_t*)d)[14] = ((uint8_t*)s)[14] ^ ((uint8_t*)k)[14];
    ((uint8_t*)d)[15] = ((uint8_t*)s)[15] ^ ((uint8_t*)k)[15];
#else
    block_copy(d, s);
    xor_block(d, k);
#endif
}

static void add_round_key( uint8_t d[N_BLOCK], const uint8_t k[N_BLOCK] )
{
    xor_block(d, k);
}

static void shift_sub_rows( uint8_t st[N_BLOCK] )
{   uint8_t tt;

    st[ 0] = s_box(st[ 0]); st[ 4] = s_box(st[ 4]);
    st[ 8] = s_box(st[ 8]); st[12] = s_box(st[12]);

    tt = st[1]; st[ 1] = s_box(st[ 5]); st[ 5] = s_box(st[ 9]);
    st[ 9] = s_box(st[13]); st[13] = s_box( tt );

    tt = st[2]; st[ 2] = s_box(st[10]); st[10] = s_box( tt );
    tt = st[6]; st[ 6] = s_box(st[14]); st[14] = s_box( tt );

    tt = st[15]; st[15] = s_box(st[11]); st[11] = s_box(st[ 7]);
    st[ 7] = s_box(st[ 3]); st[ 3] = s_box( tt );
}

static void inv_shift_sub_rows( uint8_t st[N_BLOCK] )
{   uint8_t tt;

    st[ 0] = is_box(st[ 0]); st[ 4] = is_box(st[ 4]);
    st[ 8] = is_box(st[ 8]); st[12] = is_box(st[12]);

    tt = st[13]; st[13] = is_box(st[9]); st[ 9] = is_box(st[5]);
    st[ 5] = is_box(st[1]); st[ 1] = is_box( tt );

    tt = st[2]; st[ 2] = is_box(st[10]); st[10] = is_box( tt );
    tt = st[6]; st[ 6] = is_box(st[14]); st[14] = is_box( tt );

    tt = st[3]; st[ 3] = is_box(st[ 7]); st[ 7] = is_box(st[11]);
    st[11] = is_box(st[15]); st[15] = is_box( tt );
}

#if defined( VERSION_1 )
  static void mix_sub_columns( uint8_t dt[N_BLOCK] )
  { uint8_t st[N_BLOCK];
    block_copy(st, dt);
#else
  static void mix_sub_columns( uint8_t dt[N_BLOCK], uint8_t st[N_BLOCK] )
  {
#endif
    dt[ 0] = gfm2_sb(st[0]) ^ gfm3_sb(st[5]) ^ s_box(st[10]) ^ s_box(st[15]);
    dt[ 1] = s_box(st[0]) ^ gfm2_sb(st[5]) ^ gfm3_sb(st[10]) ^ s_box(st[15]);
    dt[ 2] = s_box(st[0]) ^ s_box(st[5]) ^ gfm2_sb(st[10]) ^ gfm3_sb(st[15]);
    dt[ 3] = gfm3_sb(st[0]) ^ s_box(st[5]) ^ s_box(st[10]) ^ gfm2_sb(st[15]);

    dt[ 4] = gfm2_sb(st[4]) ^ gfm3_sb(st[9]) ^ s_box(st[14]) ^ s_box(st[3]);
    dt[ 5] = s_box(st[4]) ^ gfm2_sb(st[9]) ^ gfm3_sb(st[14]) ^ s_box(st[3]);
    dt[ 6] = s_box(st[4]) ^ s_box(st[9]) ^ gfm2_sb(st[14]) ^ gfm3_sb(st[3]);
    dt[ 7] = gfm3_sb(st[4]) ^ s_box(st[9]) ^ s_box(st[14]) ^ gfm2_sb(st[3]);

    dt[ 8] = gfm2_sb(st[8]) ^ gfm3_sb(st[13]) ^ s_box(st[2]) ^ s_box(st[7]);
    dt[ 9] = s_box(st[8]) ^ gfm2_sb(st[13]) ^ gfm3_sb(st[2]) ^ s_box(st[7]);
    dt[10] = s_box(st[8]) ^ s_box(st[13]) ^ gfm2_sb(st[2]) ^ gfm3_sb(st[7]);
    dt[11] = gfm3_sb(st[8]) ^ s_box(st[13]) ^ s_box(st[2]) ^ gfm2_sb(st[7]);

    dt[12] = gfm2_sb(st[12]) ^ gfm3_sb(st[1]) ^ s_box(st[6]) ^ s_box(st[11]);
    dt[13] = s_box(st[12]) ^ gfm2_sb(st[1]) ^ gfm3_sb(st[6]) ^ s_box(st[11]);
    dt[14] = s_box(st[12]) ^ s_box(st[1]) ^ gfm2_sb(st[6]) ^ gfm3_sb(st[11]);
    dt[15] = gfm3_sb(st[12]) ^ s_box(st[1]) ^ s_box(st[6]) ^ gfm2_sb(st[11]);
  }

#if defined( VERSION_1 )
  static void inv_mix_sub_columns( uint8_t dt[N_BLOCK] )
  { uint8_t st[N_BLOCK];
    block_copy(st, dt);
#else
  static void inv_mix_sub_columns( uint8_t dt[N_BLOCK], uint8_t st[N_BLOCK] )
  {
#endif
    dt[ 0] = is_box(gfm_e(st[ 0]) ^ gfm_b(st[ 1]) ^ gfm_d(st[ 2]) ^ gfm_9(st[ 3]));
    dt[ 5] = is_box(gfm_9(st[ 0]) ^ gfm_e(st[ 1]) ^ gfm_b(st[ 2]) ^ gfm_d(st[ 3]));
    dt[10] = is_box(gfm_d(st[ 0]) ^ gfm_9(st[ 1]) ^ gfm_e(st[ 2]) ^ gfm_b(st[ 3]));
    dt[15] = is_box(gfm_b(st[ 0]) ^ gfm_d(st[ 1]) ^ gfm_9(st[ 2]) ^ gfm_e(st[ 3]));

    dt[ 4] = is_box(gfm_e(st[ 4]) ^ gfm_b(st[ 5]) ^ gfm_d(st[ 6]) ^ gfm_9(st[ 7]));
    dt[ 9] = is_box(gfm_9(st[ 4]) ^ gfm_e(st[ 5]) ^ gfm_b(st[ 6]) ^ gfm_d(st[ 7]));
    dt[14] = is_box(gfm_d(st[ 4]) ^ gfm_9(st[ 5]) ^ gfm_e(st[ 6]) ^ gfm_b(st[ 7]));
    dt[ 3] = is_box(gfm_b(st[ 4]) ^ gfm_d(st[ 5]) ^ gfm_9(st[ 6]) ^ gfm_e(st[ 7]));

    dt[ 8] = is_box(gfm_e(st[ 8]) ^ gfm_b(st[ 9]) ^ gfm_d(st[10]) ^ gfm_9(st[11]));
    dt[13] = is_box(gfm_9(st[ 8]) ^ gfm_e(st[ 9]) ^ gfm_b(st[10]) ^ gfm_d(st[11]));
    dt[ 2] = is_box(gfm_d(st[ 8]) ^ gfm_9(st[ 9]) ^ gfm_e(st[10]) ^ gfm_b(st[11]));
    dt[ 7] = is_box(gfm_b(st[ 8]) ^ gfm_d(st[ 9]) ^ gfm_9(st[10]) ^ gfm_e(st[11]));

    dt[12] = is_box(gfm_e(st[12]) ^ gfm_b(st[13]) ^ gfm_d(st[14]) ^ gfm_9(st[15]));
    dt[ 1] = is_box(gfm_9(st[12]) ^ gfm_e(st[13]) ^ gfm_b(st[14]) ^ gfm_d(st[15]));
    dt[ 6] = is_box(gfm_d(st[12]) ^ gfm_9(st[13]) ^ gfm_e(st[14]) ^ gfm_b(st[15]));
    dt[11] = is_box(gfm_b(st[12]) ^ gfm_d(st[13]) ^ gfm_9(st[14]) ^ gfm_e(st[15]));
  }

/*  Set the cipher key for the pre-keyed version */

return_type aes_set_key( const unsigned char key[], length_type keylen, aes_context ctx[1] )
{
    uint8_t cc, rc, hi;

    switch( keylen )
    {
    case 16:
    case 128: 
        keylen = 16; 
        break;
    case 24:
    case 192: 
        keylen = 24; 
        break;
    case 32:
    case 256: 
        keylen = 32; 
        break;
    default: 
        ctx->rnd = 0; 
        return -1;
    }
    block_copy_nn(ctx->ksch, key, keylen);
    hi = (keylen + 28) << 2;
    ctx->rnd = (hi >> 4) - 1;
    for( cc = keylen, rc = 1; cc < hi; cc += 4 )
    {   uint8_t tt, t0, t1, t2, t3;

        t0 = ctx->ksch[cc - 4];
        t1 = ctx->ksch[cc - 3];
        t2 = ctx->ksch[cc - 2];
        t3 = ctx->ksch[cc - 1];
        if( cc % keylen == 0 )
        {
            tt = t0;
            t0 = s_box(t1) ^ rc;
            t1 = s_box(t2);
            t2 = s_box(t3);
            t3 = s_box(tt);
            rc = f2(rc);
        }
        else if( keylen > 24 && cc % keylen == 16 )
        {
            t0 = s_box(t0);
            t1 = s_box(t1);
            t2 = s_box(t2);
            t3 = s_box(t3);
        }
        tt = cc - keylen;
        ctx->ksch[cc + 0] = ctx->ksch[tt + 0] ^ t0;
        ctx->ksch[cc + 1] = ctx->ksch[tt + 1] ^ t1;
        ctx->ksch[cc + 2] = ctx->ksch[tt + 2] ^ t2;
        ctx->ksch[cc + 3] = ctx->ksch[tt + 3] ^ t3;
    }
    return 0;
}

/*  Encrypt a single block of 16 bytes */

return_type aesencrypt( const unsigned char in[N_BLOCK], unsigned char  out[N_BLOCK], const aes_context ctx[1] )
{
    if( ctx->rnd )
    {
        uint8_t s1[N_BLOCK], r;
        copy_and_key( s1, in, ctx->ksch );

        for( r = 1 ; r < ctx->rnd ; ++r )
#if defined( VERSION_1 )
        {
            mix_sub_columns( s1 );
            add_round_key( s1, ctx->ksch + r * N_BLOCK);
        }
#else
        {   uint8_t s2[N_BLOCK];
            mix_sub_columns( s2, s1 );
            copy_and_key( s1, s2, ctx->ksch + r * N_BLOCK);
        }
#endif
        shift_sub_rows( s1 );
        copy_and_key( out, s1, ctx->ksch + r * N_BLOCK );
    }
    else
        return -1;
    return 0;
}


/*  Decrypt a single block of 16 bytes */

return_type aesdecrypt( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK], const aes_context ctx[1] )
{
    if( ctx->rnd )
    {
        uint8_t s1[N_BLOCK], r;
        copy_and_key( s1, in, ctx->ksch + ctx->rnd * N_BLOCK );
        inv_shift_sub_rows( s1 );

        for( r = ctx->rnd ; --r ; )
#if defined( VERSION_1 )
        {
            add_round_key( s1, ctx->ksch + r * N_BLOCK );
            inv_mix_sub_columns( s1 );
        }
#else
        {   uint8_t s2[N_BLOCK];
            copy_and_key( s2, s1, ctx->ksch + r * N_BLOCK );
            inv_mix_sub_columns( s1, s2 );
        }
#endif
        copy_and_key( out, s1, ctx->ksch );
    }
    else
        return -1;
    return 0;
}

/* CBC decrypt a number of blocks (input and return an IV) */

return_type aes_cbc_decrypt( const unsigned char *in, unsigned char *out,
                         int n_block, unsigned char iv[N_BLOCK], const aes_context ctx[1] )
{   
    while(n_block--)
    {   uint8_t tmp[N_BLOCK];
        
        memcpy(tmp, in, N_BLOCK);
        if(aesdecrypt(in, out, ctx) != EXIT_SUCCESS)
			return EXIT_FAILURE;
        xor_block(out, iv);
        memcpy(iv, tmp, N_BLOCK);
        in += N_BLOCK;
        out += N_BLOCK;
    }
    return EXIT_SUCCESS;
}




void do_omac(const uint8_t key[16], const uint8_t data[], int length,
             uint8_t mac[16]);

void do_omac_n(const uint8_t key[16], const uint8_t data[], int length,
             uint8_t mac[16], uint8_t tag);

void do_ctr(const uint8_t key[16], const uint8_t nonce[16],
            uint8_t data[], int length);

void do_eax(const uint8_t key[16], const uint8_t nonce[16],
            const uint8_t data[], int length,
            const uint8_t header[], int h_length,
            uint8_t message_ciphered[],
            uint8_t tag_buf[], int tag_length);

/* The overall EAX transform */
void do_eax(const uint8_t key[16], const uint8_t nonce[16],
            const uint8_t data[], int length,
            const uint8_t header[], int h_length,
            uint8_t data_ciphered[],
            uint8_t tag_buf[], int tag_length)
   {
   uint8_t mac_nonce[16], mac_data[16], mac_header[16];
   int j;

   /* this copy will be encrypted in CTR mode */
   //uint8_t* data_copy = (uint8_t*)malloc(length);
   uint8_t data_copy [length];
   memcpy(data_copy, data, length);

   do_omac_n(key, nonce, 16, mac_nonce, 0);
   do_omac_n(key, header, h_length, mac_header, 1);
   do_ctr(key, mac_nonce, data_copy, length);
   /* MAC the ciphertext, not the plaintext */
   do_omac_n(key, data_copy, length, mac_data, 2);



   for(j = 0; j != length; j++){
	  data_ciphered[j] = data_copy[j];
   }
   for(j = 0; j != TAG_SIZE; j++){
	  tag_buf[j] = mac_nonce[j] ^ mac_data[j] ^ mac_header[j];
   }

}

/* I copied this part from my 'real' OMAC source, so it's possible they are
   both wrong - this needs to be checked carefully.
*/
void poly_double(const uint8_t in[16], uint8_t out[16])
   {
   const int do_xor = (in[0] & 0x80) ? 1 : 0;
   int j;
   uint8_t carry = 0;

   memcpy(out, in, 16);

   for(j = 16; j != 0; j--)
      {
      uint8_t temp = out[j-1];
      out[j-1] = (temp << 1) | carry;
      carry = (temp >> 7);
      }

   if(do_xor)
      out[15] ^= 0x87; /* fixed polynomial for n=128, binary=10000111 */
   }

/* The OMAC parameterized PRF function */
void do_omac_n(const uint8_t key[16], const uint8_t data[], int length,
               uint8_t mac[16], uint8_t tag)
   {
   //uint8_t* data_copy = (uint8_t*)malloc(length + 16);
   uint8_t data_copy [length + 16];

   memset(data_copy, 0, length + 16);
   data_copy[15] = tag;
   memcpy(data_copy + 16, data, length);

   do_omac(key, data_copy, length + 16, mac);
   }

/* The OMAC / pad functions */
void do_omac(const uint8_t key[16], const uint8_t data[], int length,
             uint8_t mac[16])
   {

   aes_context ctx;


   
   uint8_t L[16] = { 0 }, P[16] = { 0 }, B[16] = { 0 };
   int j;
   int total_len = 0;

   uint8_t data_padded [150];
   const uint8_t* xor_pad;

   //AES_set_encrypt_key(key, 128, &aes_key);
   aes_set_key(key, 16, &ctx);

   //AES_encrypt(L, L, &aes_key); /* create L */
   aesencrypt(L, L, &ctx);

   poly_double(L, B); /* B = 2L */
   poly_double(B, P); /* P = 2B = 2(2L) = 4L */

   if(length && length % 16 == 0) /* if of size n, 2n, 3n... */
      total_len = length; /* no padding */
   else
      total_len = length + (16 - length % 16); /* round up to next 16 uint8_ts */


   memset(data_padded, 0, total_len);
   memcpy(data_padded, data, length);

   if(total_len != length) /* if add padding */
      data_padded[length] = 0x80;


   /* If no padding, XOR in B, otherwise XOR in P */
   xor_pad = (total_len == length) ? B : P;

   for(j = total_len - 16; j != total_len; j++)
      {
      data_padded[j] ^= *xor_pad;
      xor_pad++;
      }


   memset(mac, 0, 16);

   for(j = 0; j != total_len; j += 16)
      {
      int k;
      for(k = 0; k != 16; k++) mac[k] ^= data_padded[j+k];

   	  aesencrypt(mac, mac, &ctx);
      }

   }

/* CTR encryption */
void do_ctr(const uint8_t key[16], const uint8_t nonce[16],
            uint8_t data[], int length)
   {
   aes_context ctx;

   uint8_t state[16]; /* the actual counter */
   uint8_t buffer[16]; /* encrypted counter */
   int j;

   memcpy(state, nonce, 16);

   //AES_set_encrypt_key(key, 128, &aes_key);
   aes_set_key(key, 16, &ctx);
   
   /* Initial encryption of the counter */
   aesencrypt(state, buffer, &ctx);

   while(length)
      {
      int to_xor = (length < 16) ? length : 16;

      for(j = 0; j != to_xor; j++)
         data[j] ^= buffer[j];
      data += to_xor;
      length -= to_xor;

      /* Compute E(counter++) */
      for(j = 15; j >= 0; j--)
         if(++state[j])
            break;
     aesencrypt(state, buffer, &ctx);
      }
   }


//
//#include "includes.h"
//#include "./includes/wpa_supplicant/src/utils/includes.h"
//#include "./includes/wpa_supplicant/src/utils/wpa_debug.h"

//#include "common.h"
//#include "./includes/wpa_supplicant/src/utils/common.h"

//#include "crypto/aes_wrap.h"
//#include "./includes/wpa_supplicant/src/crypto/aes_wrap.h"

#include "eap_psk_common.h"
#include "aes.h"
#include "eax.h"

#define MPPE_KEY_LEN    32
#define MSK_EMSK_LEN    (2*MPPE_KEY_LEN)

#include <sys/time.h>

// Comment this line to disable time measurement.
#define MEASURE_TIME

#ifdef MEASURE_TIME
struct timeval start, end;
double total_time_taken = 0.0;
#endif

static void write_file(double result) {

    FILE *file = fopen("../../tests/internal_times_server.txt", "a");
    
    if (file == NULL) {
        printf("ERROR OPENING FILE\n");
        return;
    }
    
    fprintf(file, "%f\n", result);
    
    fclose(file);
}


typedef struct rlm_eap_psk_t {

	enum { PSK_1, PSK_3, SUCCESS, FAILURE } state;

	uint8_t *psk;
	uint8_t rand_s[EAP_PSK_RAND_LEN];
	uint8_t rand_p[EAP_PSK_RAND_LEN];
	
	uint8_t mac_p[EAP_PSK_MAC_LEN];
	uint8_t mac_s[EAP_PSK_MAC_LEN];

	uint8_t *id_p, *id_s, *pchannel0;
	size_t id_p_len, id_s_len;

	uint8_t ak[EAP_PSK_AK_LEN], 
			kdk[EAP_PSK_KDK_LEN], 
			tek[EAP_PSK_TEK_LEN],
			msk[64],
			emsk[64];


	uint8_t step;


} rlm_eap_psk_t;


void printf_hex(uint8_t* text, int length);
void printf_hex(uint8_t* text, int length) {
    int i;
    for(i=0; i<length; i++)
        printf("%02X",text[i]);
    printf("\n");
    return;
}

/*
static uint8_t psk[16]={'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};

unsigned char output [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Auxiliar AES register
uint8_t it;
uint16_t aux;
static uint8_t data [64];


//static unsigned char ak [16];
//static unsigned char kdk [16];

static uint8_t step;
static unsigned char rand_s[16];
static unsigned char rand_p[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static unsigned char id_s[16];
static unsigned short id_s_length;

//Nonce defined in the RFC EAP-PSK for the protected-channel computing
static unsigned char nonce [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static unsigned char data_ciphered [16];
static unsigned char tag_bug[16];
static unsigned char header [22];
static unsigned char msg[1] = {0x80};
*/
#define MSK_LENGTH  64 //16 uint8_ts due to AES key length

uint8_t msk_key [64];
uint8_t emsk_key [64];

struct eap_psk_hdr_3 send2peer = {0};
struct eap_psk_hdr_2 *received_from_peer = NULL;

uint8_t ct[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t output [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Auxiliar AES register

    //AesCtx ctx; //Aes context
    aes_context ctx;


void initMethodEap(rlm_eap_psk_t *inst){
/*
	uint8_t aux = 0;
	inst->state = 0;



	//Init variables
	inst->step = 0; //In the beginning there is no eap-psk message
	inst->psk = strdup("IoTWorldForum-22");

	//Init the Aes ctx with the psk
	aes_set_key(inst->psk, 16, &ctx);

	uint8_t it = 0;
	//Init the rand_p
	for (it=0; it<16; it=it+2){
		srand(time(NULL));
		aux = rand();
		memcpy(inst->rand_p+it, &aux, sizeof(unsigned short)); //2 uint8_ts
	}
	
	///////AK and KDK derivation

	//Init constant as ct0
	memset(ct, 0, sizeof(ct));

	/////AES-128(PSK,ct0)
	aesencrypt(ct, output, &ctx);

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	/////XOR (ct1, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	////AK = AES-128(PSK, XOR (ct1, AES-128(PSK, ct0)))
	aesencrypt(ct, inst->ak, &ctx);

	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	/////XOR (ct2, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	////KDK = AES-128 (PSK, XOR (ct2, AES-128(PSK, ct0)) )
	aesencrypt(ct, inst->kdk, &ctx);
	aes_set_key(inst->kdk, 16, &ctx);
	aesencrypt(received_from_peer->rand_p, output, &ctx);

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	//XOR (ct1, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}


	aesencrypt(ct, inst->tek, &ctx);

	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	//XOR (ct2, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

    aesencrypt(ct, inst->tek, &ctx);

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x02;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    
    aesencrypt(ct, msk_key, &ctx);
*/


        //Init variables
    //psk_key_available = FALSE; //In the beginning there is no key
//    step = 0; //In the beginning there is no eap-psk message
    uint8_t raw_psk[] = {
        0x06, 0xb4, 0xbe, 0x19, 0xda, 0x28, 0x9f, 0x47,
        0x5a, 0xa4, 0x6a, 0x33, 0xcb, 0x79, 0x30, 0x29
    };

    inst->psk = malloc(sizeof(raw_psk));
    if (inst->psk != NULL) {
        memcpy(inst->psk, raw_psk, sizeof(raw_psk));
    }
    aes_set_key(inst->psk, 16, &ctx);

    //Init the rand_p
    uint8_t it = 0;
    //uint16_t aux;
    //Init the rand_p
    /*
    for (it=0; it<16; it=it+2){
        srand(time(NULL));
        aux = rand();
        memcpy(inst->rand_p+it, &aux, sizeof(unsigned short)); //2 uint8_ts
    }
    */
    ///////AK and KDK derivation

    //Init constant as ct0
    memset(ct, 0, sizeof(ct));


    aesencrypt(ct, output, &ctx);

    //Init constant as ct1
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x01;
    
    /////XOR (ct1, AES-128(PSK, ct0))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, inst->ak, &ctx);

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x02;
    
    /////XOR (ct2, AES-128(PSK, ct0))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }


    aesencrypt(ct, inst->kdk, &ctx);


    
    aes_set_key(inst->kdk, 16, &ctx);


    aesencrypt(inst->rand_p, output, &ctx);

    //Init constant as ct1
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x01;
    
    //XOR (ct1, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }


    aesencrypt(ct, inst->tek, &ctx);

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x02;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, msk_key, &ctx);

    // Round 2

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x03;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, msk_key+16, &ctx);


    // Round 3

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x04;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, msk_key+32, &ctx);

    // Round 4

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x05;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, msk_key+48, &ctx);

    printf("The MSK key is:\n");
    printf_hex(msk_key, MSK_LENGTH);

    // Round 5

    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x06;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, emsk_key, &ctx);


    // Round 6
    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x07;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, emsk_key+16, &ctx);

    // Round 7
    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x08;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, emsk_key+16+16, &ctx);

    // Round 8
    //Init constant as ct2
    memset(ct, 0, sizeof(ct));
    ct[15] = 0x09;
    
    //XOR (ct2, AES-128(KDK, RAND_P))
    for (it=0; it<16; it++){
        ct[it] = ct[it]^output[it];
    }

    aesencrypt(ct, emsk_key+16+16+16, &ctx);




	printf("EAP-PSK: AK\n");
	printf_hex(inst->ak, EAP_PSK_AK_LEN);
	
	printf("EAP-PSK: KDK\n");
	printf_hex(inst->kdk, EAP_PSK_KDK_LEN);
	printf("____________________________\n");

    printf("EAP-PSK: TEK\n");
    printf_hex(inst->tek, EAP_PSK_TEK_LEN);
    printf("____________________________\n");

    printf("EAP-PSK: MSK\n");
    printf_hex(msk_key, MSK_LENGTH);
    printf("____________________________\n");

    printf("EAP-PSK: EMSK\n");
    printf_hex(emsk_key, MSK_LENGTH);
    printf("____________________________\n");





}



/*
 *	Attach the EAP-DUMMY module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
    printf("EAP PSK Instantiate");

	rlm_eap_psk_t		*inst;

	/*
	 *	Parse the config file & get all the configured values
	 */
	*instance = inst = talloc_zero(cs, rlm_eap_psk_t);
	if (!inst) return -1;

	inst->state = PSK_1;
	inst->id_s = (uint8_t *) "FreeRADIUS";
	inst->id_s_len = 10;


	//uint8_t *password = strdup("IoTWorldForum-22");
/*
	if (eap_psk_key_setup(password, inst->ak, inst->kdk)) {
		printf("ERROR setting up KEY material\n");
		return NULL;
	}
	*/

return 0;
}


int os_get_random(unsigned char *buf, size_t len);
int os_get_random(unsigned char *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "rb");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}


/*
 *	Initiate the EAP-PSK session by sending a challenge to the peer.
 */
static int mod_session_init_psk(void *type_arg, eap_handler_t *handler)
{

	printf("_____________ mod_session_init_psk\n");


    #ifdef MEASURE_TIME
    total_time_taken = 0.0;
    // Record the start time
    gettimeofday(&start, NULL);
    #endif

	rlm_eap_psk_t *inst;
	inst = type_arg;
	struct eap_psk_hdr_1 psk = {0};

	printf("EAP-PSK: PSK-1 (sending)\n");

	if (os_get_random(inst->rand_s, EAP_PSK_RAND_LEN)) {
		printf("EAP-PSK: Failed to get random data");
		inst->state = FAILURE;
		return NULL;
	}


	printf( "EAP-PSK: RAND_S (server rand)");
	printf_hex(inst->rand_s, EAP_PSK_RAND_LEN);


	handler->eap_ds->request->code  		= PW_EAP_REQUEST; 
	handler->eap_ds->request->type.num  	= PW_EAP_PSK; // EAP-PSK ID
	handler->eap_ds->request->type.data 	= talloc_array(handler->eap_ds->request,
														  	uint8_t,
							  								sizeof(psk) + inst->id_s_len);

	
	psk.flags = EAP_PSK_FLAGS_SET_T(0); /* T=0 */
	memcpy(psk.rand_s, inst->rand_s, EAP_PSK_RAND_LEN);
	handler->eap_ds->request->type.length = sizeof(psk) + inst->id_s_len;
	printf("Size of PSK1 %d\n",handler->eap_ds->request->type.length);

	uint8_t *psk1_msg = malloc(handler->eap_ds->request->type.length);
	memset(psk1_msg,0,handler->eap_ds->request->type.length);
	memcpy(psk1_msg,&psk,sizeof(psk));
	memcpy(psk1_msg + sizeof(psk), inst->id_s,inst->id_s_len);

	printf("MGS1 Content \n");
	printf_hex(psk1_msg, sizeof(psk)+inst->id_s_len);

	memcpy(handler->eap_ds->request->type.data, psk1_msg, sizeof(psk)+inst->id_s_len);

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */

    #ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif

	handler->stage = PROCESS;
	return 1;
}

struct eap_msg{
    uint8_t code;
    uint8_t id;
    unsigned short length;
    uint8_t method;
}__attribute__((packed));

#define EAP_MSG_LEN 100
uint8_t eapRespData [EAP_MSG_LEN];

/*
 *	Authenticate a previously sent challenge.
 */
static int mod_process_psk(void *type_arg, eap_handler_t *handler)
{

	printf("_____________ mod_process_psk\n");

    #ifdef MEASURE_TIME
    // Record the start time
    gettimeofday(&start, NULL);
    #endif

	rlm_eap_psk_t *inst;
	inst = type_arg;

	PSK_PACKET	*packet;
	PSK_PACKET	*reply;
	VALUE_PAIR	*password;
	REQUEST		*request = handler->request;

	printf("Received from EAP peer: \n");

	printf(": \n");
	printf("ID:  %d\n",handler->eap_ds->response->id);
	printf("length:  %d\n",handler->eap_ds->response->length);
	printf("type.num:  %d\n",handler->eap_ds->response->type.num);
	printf("type.length:  %d\n",handler->eap_ds->response->type.length);
	printf("type.data:  %02X\n");
	printf_hex(handler->eap_ds->response->type.data,handler->eap_ds->response->type.length);
	////////////////////////////

	if(inst->state  == 0){

		received_from_peer = 
			(struct eap_psk_hdr_2*) handler->eap_ds->response->type.data;
		
		printf("Content of the struct in the buffer \n");
		printf_hex(received_from_peer, EAP_PSK_RAND_LEN+EAP_PSK_RAND_LEN+EAP_PSK_MAC_LEN);

		printf("flags: %02X\n",received_from_peer->flags);

		printf("rand_s\n");
		printf_hex(received_from_peer->rand_s, EAP_PSK_RAND_LEN);
		memcpy(inst->rand_s, received_from_peer->rand_s, EAP_PSK_RAND_LEN);

		printf("rand_p\n");
		printf_hex(received_from_peer->rand_p, EAP_PSK_RAND_LEN);
		memcpy(inst->rand_p, received_from_peer->rand_p, EAP_PSK_RAND_LEN);

        printf("inst->rand_p\n");
        printf_hex(inst->rand_p, EAP_PSK_RAND_LEN);

		printf("mac_p\n");
		printf_hex(received_from_peer->mac_p, EAP_PSK_MAC_LEN);
		memcpy(inst->mac_p, received_from_peer->mac_p, EAP_PSK_MAC_LEN);


		inst->id_p_len = (handler->eap_ds->response->type.length-sizeof(struct eap_psk_hdr_2));
		printf("id_p_len: %d \n",inst->id_p_len);
		inst->id_p = malloc(inst->id_p_len+1);

		memset(inst->id_p,0,inst->id_p_len+1);
		memcpy(inst->id_p, handler->eap_ds->response->type.data+1+EAP_PSK_RAND_LEN+EAP_PSK_RAND_LEN+EAP_PSK_MAC_LEN,inst->id_p_len);
		printf("id_p: %s\n", inst->id_p,inst->id_p_len);


        initMethodEap(inst);

//// Now we create the third message
//
//    |                     Flags||RAND_S||MAC_S||PCHANNEL_S_0   |
//    |<---------------------------------------------------------|
	/*
	struct eap_psk_hdr_3 {
		uint8_t flags;
		uint8_t rand_s[EAP_PSK_RAND_LEN];
		uint8_t mac_s[EAP_PSK_MAC_LEN];
		// Followed by variable length PCHANNEL 
	} __attribute__ ((packed));
	*/
		send2peer.flags = EAP_PSK_FLAGS_SET_T(2);

		memcpy(send2peer.rand_s, inst->rand_s, EAP_PSK_RAND_LEN);

	    // MAC_S = CMAC-AES-128(AK, ID_S||RAND_P)
		//memcpy(data, id_p, ID_P_LENGTH);
		
        printf("EAP-PSK: AK\n");
        printf_hex(inst->ak, EAP_PSK_AK_LEN);
        
        printf("EAP-PSK: KDK\n");
        printf_hex(inst->kdk, EAP_PSK_KDK_LEN);

        printf("EAP-PSK: ID_S\n");
        printf_hex(inst->id_s, inst->id_s_len);

        printf("EAP-PSK: RAND_P\n");
        printf_hex(received_from_peer->rand_p, EAP_PSK_RAND_LEN);

      

        uint8_t data [64];
        memset(data, 0, 64);
		
        printf("EAP-PSK: DATA\n");
        printf_hex(data, 64);
        
        memcpy(data, inst->id_s, inst->id_s_len);

        printf("EAP-PSK: DATA\n");
        printf_hex(data, 64);

		memcpy(data+inst->id_s_len, received_from_peer->rand_p, EAP_PSK_RAND_LEN);

        printf("EAP-PSK: ID_S || RAND_P\n");
        printf_hex(data, 64);

        uint8_t output [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Auxiliar AES register
       	do_omac(inst->ak, data, inst->id_s_len+EAP_PSK_RAND_LEN, output); //output == mac_p

        memcpy(send2peer.mac_s, output, EAP_PSK_MAC_LEN);
        printf("MAC_S: \n");
        printf_hex(send2peer.mac_s, EAP_PSK_MAC_LEN);

        /// Now we calculate the PCHANNEL_0

        //Nonce defined in the RFC EAP-PSK for the protected-channel computing
        // Nonce (4 bytes)
        unsigned char nonce [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        //                                     
        unsigned char   tag_bug[16];
#define EAP_PSK_R_FLAG_DONE_SUCCESS 2

        uint8_t         eapReqData[38];
        unsigned char   header [38];
        unsigned char   data_ciphered [16];
        unsigned char   msg[1] = {0x80};


        ((struct eap_msg *)eapRespData)->code = 1;
        ((struct eap_msg *)eapRespData)->id = handler->eap_ds->response->id+1;
        ((struct eap_msg *)eapRespData)->length = HTONS(59);
        ((struct eap_msg *)eapRespData)->method = 47;
        memcpy(&eapRespData[5], msg,1); //T=2 Flags
        memcpy(&eapRespData[6],inst->rand_s, 16);
        
        printf("_________________\n");
        printf("eapRespData \n");
        printf_hex(eapRespData, 22);


        memcpy(header, &eapRespData, 22);
        do_eax(inst->tek, nonce,
        msg, 1,
        header, 22,
        data_ciphered,
        tag_bug, 16);

        

		handler->eap_ds->request->code  		= PW_EAP_REQUEST; 
		handler->eap_ds->request->type.num  	= PW_EAP_PSK; // EAP-PSK ID
		handler->eap_ds->request->type.data 	= talloc_array(handler->eap_ds->request,
															  	uint8_t,
                                                            sizeof(send2peer) + 21);



    handler->eap_ds->request->type.length = sizeof(send2peer) + 21;
    printf("Size of PSK3 %d\n",handler->eap_ds->request->type.length);

    uint8_t *psk3_msg = malloc(handler->eap_ds->request->type.length);
    memset(psk3_msg,0,handler->eap_ds->request->type.length);
    memcpy(psk3_msg,&send2peer,sizeof(send2peer));
    memcpy(psk3_msg + sizeof(send2peer) + 4, tag_bug, 16);
    memcpy(psk3_msg + sizeof(send2peer) + 4 + 16 , data_ciphered, 1);

    printf("MGS3 Content \n");
    printf_hex(psk3_msg, sizeof(send2peer)+21);

    memcpy(handler->eap_ds->request->type.data, psk3_msg, sizeof(send2peer)+21);


/*
        memcpy(handler->eap_ds->request->type.data, header, 38);
        printf("Assembling eapRespData - adding header\n");
        printf_hex(handler->eap_ds->request->type.data,  59);
    
        memcpy(handler->eap_ds->request->type.data+38+4, tag_bug, 16);
        printf("Assembling eapRespData - adding tag after nonce\n");
        printf_hex(handler->eap_ds->request->type.data,  59);

        memcpy(handler->eap_ds->request->type.data+38+4+1, data_ciphered, 1);
        printf("Assembling eapRespData - adding data_ciphered\n");
        printf_hex(handler->eap_ds->request->type.data,  59);
*/

    inst->state++;

    #ifdef MEASURE_TIME
    gettimeofday(&end, NULL);  // Record the end time

    // Calculate the time difference
    double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;

    total_time_taken += time_taken;
    #endif

	}
	else{

        printf("Received EAP-PSK 4\n");

        handler->eap_ds->request->code = PW_EAP_SUCCESS;

        eap_add_reply(handler->request, "MS-MPPE-Recv-Key", msk_key,32);
        eap_add_reply(handler->request, "MS-MPPE-Send-Key", msk_key+32,32);

        #ifdef MEASURE_TIME
        gettimeofday(&end, NULL);  // Record the end time

        // Calculate the time difference
        double time_taken = (end.tv_sec - start.tv_sec) * 1.0 + 
                            (end.tv_usec - start.tv_usec) / 1000000.0;

        total_time_taken += time_taken;
        write_file(total_time_taken);
        #endif

	}

	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_psk;
rlm_eap_module_t rlm_eap_psk = {
	.name		= "eap_psk",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init_psk,	/* Initialise a new EAP session */
	.process		= mod_process_psk		/* Process next round of EAP method */
};
