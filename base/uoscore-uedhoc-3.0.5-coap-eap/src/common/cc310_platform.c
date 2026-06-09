// cc310_platform.c

#if defined(CC310)
#include <zephyr/kernel.h>
#include <soc.h>
#include "sns_silib.h" // SaSi_LibInit(), SaSi_LibFini()
#include "crys_rnd.h"

static K_MUTEX_DEFINE(cc310_mutex);
static bool cc310_on;
static bool we_started_hfclk;

/* --- RNG global y flag --- */
CRYS_RND_State_t g_cc310_rnd_state;
CRYS_RND_WorkBuff_t g_cc310_rnd_work;
static bool g_rnd_ready;
static bool g_lib_ready;

static void hfclk_start(void)
{
        if ((NRF_CLOCK->HFCLKSTAT & CLOCK_HFCLKSTAT_STATE_Msk) &&
            ((NRF_CLOCK->HFCLKSTAT & CLOCK_HFCLKSTAT_SRC_Msk) ==
             (CLOCK_HFCLKSTAT_SRC_Xtal << CLOCK_HFCLKSTAT_SRC_Pos)))
        {
                we_started_hfclk = false;
                return;
        }
        NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
        NRF_CLOCK->TASKS_HFCLKSTART = 1;
        while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0)
        { /* wait */
        }
        we_started_hfclk = true;
}

static void hfclk_stop(void)
{
        if (we_started_hfclk)
        {
                NRF_CLOCK->TASKS_HFCLKSTOP = 1;
                we_started_hfclk = false;
        }
}

static void cc310_enable(void) { NRF_CRYPTOCELL->ENABLE = 1; }
static void cc310_disable(void) { NRF_CRYPTOCELL->ENABLE = 0; }

void cc310_hw_acquire(void)
{
        k_mutex_lock(&cc310_mutex, K_FOREVER);
        if (!cc310_on)
        {
                hfclk_start();
                cc310_enable();

                if (!g_lib_ready)
                {
                        /* 1) Inicializa la librería */
                        if (SaSi_LibInit() == 0)
                        {
                                g_lib_ready = true;
                        }
                }
                if (g_lib_ready && !g_rnd_ready)
                {
                        /* 2) IMPORTANTE: Instanciar RNG DESPUÉS de LibInit y con CCELL activo */
                        /* En 0.9.13, la función suele llamarse CRYS_RND_Instantiation */
                        if (CRYS_RND_Instantiation(&g_cc310_rnd_state, &g_cc310_rnd_work) == CRYS_OK)
                        {
                                g_rnd_ready = true;
                        }
                }
                cc310_on = true;
        }
}

void cc310_hw_release(void)
{
        /* Mantén la lib y el RNG instanciados para evitar re-seed constante */
        cc310_disable();
        hfclk_stop();
        cc310_on = false;
        k_mutex_unlock(&cc310_mutex);
}
#else
        static int cc310_platform_dummy __attribute__((unused));
#endif

