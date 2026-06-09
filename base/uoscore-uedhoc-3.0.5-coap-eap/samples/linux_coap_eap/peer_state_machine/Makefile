all: udp-client udp-server

UIP_CONF_IPV6=1

PROJECT_SOURCEFILES= eap-peer.c eap-psk.c eax.c aes.c

CFLAGS += -ffunction-sections 
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

