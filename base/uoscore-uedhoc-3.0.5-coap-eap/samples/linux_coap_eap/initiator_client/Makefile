# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# in order to rebuild the uoscore-uedhoc.a and client application call: 
# make oscore_edhoc; make

include ../../../makefile_config.mk

# toolchain
CXX ?= g++
CC ?= gcc
SZ ?= size
MAKE ?= make

# target
TARGET = initiator_client

# build path
BUILD_DIR = build

# libusocore-uedhoc path
USOCORE_UEDHOC_PATH = ../../../
USOCORE_UEDHOC_BUILD_PATH = $(USOCORE_UEDHOC_PATH)build

ifeq ($(ARCH_32_ONLY), 1)
# build for 32 bit x68 
# export the varible so that it is availbale in the uoscore-uedhoc Makefile 
ARCH = -m32
export ARCH
endif

# debug build?
DEBUG = 1

# optimization
OPT = -Og

WPA_SUPPLICANT_ROOT = ../hostap
WPA_SUPPLICANT_SRC_PATH = $(WPA_SUPPLICANT_ROOT)/src
WPA_SUPPLICANT_BUILD_PATH = $(WPA_SUPPLICANT_ROOT)/wpa_supplicant

# CPP sources
CPP_SOURCES += src/main.cpp
CPP_SOURCES += ../../../externals/cantcoap/cantcoap.cpp
CPP_SOURCES += ../coap_transport/coap_transport.cpp

# C sources 
# rename files avaible with the same name in diferent libraries
# $(shell mv ../../../externals/compact25519/src/c25519/sha512.c ../../../externals/compact25519/src/c25519/_sha512.c )

C_SOURCES += $(wildcard ../../common/*.c)
C_SOURCES += $(wildcard ../../../externals/zcbor/src/*.c)
C_SOURCES += $(wildcard ../../../test_vectors/*.c)

C_SOURCES += ../eap_methods/eap_methods.c
C_SOURCES += ../radius_transport/radius_transport.c
C_SOURCES += ../oscore_context/oscore_context.c

# RADIUS integration
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/crypto/crypto_linux.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/crypto/os_unix.c

C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/utils/common.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/utils/eloop.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/utils/ip_addr.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/utils/wpabuf.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/utils/wpa_debug.c

C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/radius/radius.c
C_SOURCES += $(WPA_SUPPLICANT_SRC_PATH)/radius/radius_client.c

# Crypto engine dependent source files
ifeq ($(findstring COMPACT25519,$(CRYPTO_ENGINE)),COMPACT25519) 
C_SOURCES += $(wildcard ../../../externals/compact25519/src/c25519/*.c)
C_SOURCES += $(wildcard ../../../externals/compact25519/src/*.c)
endif

ifeq ($(findstring TINYCRYPT,$(CRYPTO_ENGINE)),TINYCRYPT)
C_SOURCES += $(wildcard ../../../externals/tinycrypt/lib/source/*.c)
endif
 
ifeq ($(findstring MBEDTLS,$(CRYPTO_ENGINE)),MBEDTLS)
C_SOURCES += $(wildcard ../../../externals/mbedtls/library/*.c)
endif

# C includes
C_INCLUDES += -I../../../inc/
C_INCLUDES += -I../../../inc/common/
C_INCLUDES += -I../../../inc/edhoc/
C_INCLUDES += -I../../common/
C_INCLUDES += -I../../../test_vectors/ 
C_INCLUDES += -I../../../externals/cantcoap/ 
C_INCLUDES += -I../../../externals/zcbor/include/
C_INCLUDES += -I../coap_transport/
C_INCLUDES += -I../hostap/src/radius/
C_INCLUDES += -I../hostap/src/utils/
C_INCLUDES += -I../eap_methods/
C_INCLUDES += -I../peer_state_machine/
C_INCLUDES += -I../radius_transport/
C_INCLUDES += -I../oscore_context/

# Crypto engine dependent includes
ifeq ($(findstring COMPACT25519,$(CRYPTO_ENGINE)),COMPACT25519) 
C_INCLUDES += -I../../../externals/compact25519/src/c25519/ 
C_INCLUDES += -I../../../externals/compact25519/src/ 
endif

ifeq ($(findstring TINYCRYPT,$(CRYPTO_ENGINE)),TINYCRYPT)
C_INCLUDES += -I../../../externals/tinycrypt/lib/include
endif
 
ifeq ($(findstring MBEDTLS,$(CRYPTO_ENGINE)),MBEDTLS)
C_INCLUDES += -I../../../externals/mbedtls/library 
C_INCLUDES += -I../../../externals/mbedtls/include 
C_INCLUDES += -I../../../externals/mbedtls/include/mbedtls 
C_INCLUDES += -I../../../externals/mbedtls/include/psa 
endif

C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/ap
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/common
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/crypto
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/drivers
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/eap_common
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/eap_peer
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/eap_server
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/eapol_auth
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/eapol_supp
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/l2_packet
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/radius
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/rsn_supp
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/tls
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/utils
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/src/wps
C_INCLUDES += -I$(WPA_SUPPLICANT_ROOT)/wpa_supplicant

# C defines
# make PRINT_ARRAY macro usable in the main file
C_DEFS += -DDEBUG_PRINT
C_DEFS += -DLINUX_SOCKETS

# Linked libraries
LD_LIBRARY_PATH += -L$(USOCORE_UEDHOC_BUILD_PATH)

LDFLAGS += $(LD_LIBRARY_PATH)
LDFLAGS += -luoscore-uedhoc
LDFLAGS += $(ARCH)

LDFLAGS += -L$(WPA_SUPPLICANT_SRC_PATH)
LDFLAGS += -L$(WPA_SUPPLICANT_BUILD_PATH)

##########################################
# CFLAGS
##########################################
#general c flags
CFLAGS +=  $(ARCH) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall
CXXFLAGS +=  $(ARCH) $(C_DEFS) $(C_INCLUDES) $(OPT)

# have dubug information
ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2
CXXFLAGS += -Wall -g
endif

# Generate dependency information
CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"
CXXFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" 

# required for gddl-gen library
CFLAGS += -DZCBOR_CANONICAL 



# use AddressSanitizer to find memory bugs
# comment this out for better speed
#CFLAGS += -fsanitize=address -fno-omit-frame-pointer
#CXXFLAGS += -fsanitize=address -fno-omit-frame-pointer
#LDFLAGS += -fsanitize=address -static-libasan

###########################################
# default action: build all
###########################################
#list of objects from c files
OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

# list of objects from c++ file
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(CPP_SOURCES:.cpp=.o)))
vpath %.cpp $(sort $(dir $(CPP_SOURCES)))

USOCORE_UEDHOC_OBJ = $(wildcard $(USOCORE_UEDHOC_PATH)/*.o) 



$(BUILD_DIR)/%.o: %.cpp Makefile | $(BUILD_DIR) 
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR) 
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

# $(BUILD_DIR)/$(TARGET): $(OBJECTS) Makefile $(USOCORE_UEDHOC_PATH)/Makefile $(USOCORE_UEDHOC_OBJ)
# 	$(MAKE) -C $(USOCORE_UEDHOC_PATH)
# 	$(CXX) $(OBJECTS)  $(LDFLAGS) -o $@
# 	$(SZ) $@

$(BUILD_DIR)/$(TARGET): $(OBJECTS) Makefile $(USOCORE_UEDHOC_PATH)/Makefile $(USOCORE_UEDHOC_OBJ)
	$(MAKE) -C $(USOCORE_UEDHOC_PATH)
	$(MAKE) -C $(WPA_SUPPLICANT_SRC_PATH)
	$(MAKE) -C $(WPA_SUPPLICANT_BUILD_PATH)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@

$(BUILD_DIR):
	mkdir $@



oscore_edhoc:
	$(MAKE) -C $(USOCORE_UEDHOC_PATH)

clean_oscore_edhoc:
	$(MAKE) -C $(USOCORE_UEDHOC_PATH) clean

clean:
	-rm -fR $(BUILD_DIR)
	$(MAKE) -C $(USOCORE_UEDHOC_PATH) clean
	$(MAKE) -C $(WPA_SUPPLICANT_SRC_PATH) clean
	$(MAKE) -C $(WPA_SUPPLICANT_BUILD_PATH) clean

#######################################
# dependencies
#######################################
-include $(wildcard $(BUILD_DIR)/*.d)
