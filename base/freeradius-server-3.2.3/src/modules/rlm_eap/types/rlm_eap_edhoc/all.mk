TARGETNAME	:= rlm_eap_edhoc

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c
## ^ Basico no se toca

#DEFS	:= ZCBOR_CANONICAL

# uEDHOC integration: includes ==========
include ../uoscore-uedhoc/makefile_config.mk

EDHOC_DIR := ../uoscore-uedhoc

ZCBOR_DIR := ${EDHOC_DIR}/externals/zcbor
ZCBOR_INCLUDES := -I${ZCBOR_DIR}/include

MBEDTLS_DIR := ${EDHOC_DIR}/externals/mbedtls
MBEDTLS_INCLUDES := -I${MBEDTLS_DIR}/library -I${MBEDTLS_DIR}/include -I${MBEDTLS_DIR}/include/mbedtls -I${MBEDTLS_DIR}/include/psa

COMPACT25519_DIR := ${EDHOC_DIR}/externals/compact25519/src
COMPACT25519_INCLUDES := -I${COMPACT25519_DIR}/c25519/ -I${COMPACT25519_DIR} 

TINYCRYPT_DIR := -I${EDHOC_DIR}/externals/tinycrypt
TINYCRYPT_INCLUDES := -I${TINYCRYPT_DIR}lib/include

EX_INCLUDES := ${TINYCRYPT_INCLUDES}
EX_INCLUDES += ${COMPACT25519_INCLUDES}
EX_INCLUDES += ${MBEDTLS_INCLUDES}
EX_INCLUDES += ${ZCBOR_INCLUDES}

EDHOC_INCLUDES := -I${EDHOC_DIR}/inc 
EDHOC_INCLUDES += -I${EDHOC_DIR}/common
EDHOC_INCLUDES += -I${EDHOC_DIR}/test_vectors 
EDHOC_INCLUDES += ${EX_INCLUDES}
SRC_CFLAGS := $(EDHOC_INCLUDES) $(FEATURES)
# ===================================

#TGT_LDLIBS	:=  -lrt ./src/modules/rlm_eap/types/rlm_eap_edhoc/libuedhoc.a

OBJS_uedhoc := $(wildcard ${EDHOC_DIR}/samples/linux_edhoc/responder/build/*.o)
OBJS_uedhoc += $(wildcard ${EDHOC_DIR}/build/*.o)

TGT_LDLIBS := ${OBJS_uedhoc}

SRC_INCDIRS	:= ../../ ../../libeap/
TGT_PREREQS	:= libfreeradius-eap.a
