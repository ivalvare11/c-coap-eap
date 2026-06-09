// cc310_platform.h
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "crys_rnd.h"

#ifdef __cplusplus
extern "C"
{
#endif
        void cc310_hw_acquire(void);
        void cc310_hw_release(void);

        /* Exponer el estado RNG para ECDSA */
        extern CRYS_RND_State_t g_cc310_rnd_state;
#ifdef __cplusplus
}
#endif
