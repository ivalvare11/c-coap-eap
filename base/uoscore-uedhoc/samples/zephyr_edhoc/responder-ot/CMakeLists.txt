# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(responder-ot)

#target_include_directories(app PRIVATE src)


target_include_directories(app PRIVATE src
	$ENV{ZEPHYR_BASE}/subsys/net/ip
	inc
	../../common
	../../../test_vectors)
#	../../edhoc-psk/base/uoscore-uedhoc-3.0.5-psk-v2/inc
#	../../edhoc-psk/base/uoscore-uedhoc-3.0.5-psk-v2/samples/common
#	../../edhoc-psk/base/uoscore-uedhoc-3.0.5-psk-v2/test_vectors)


add_definitions(
	-DDEBUG_PRINT
	-DZCBOR_CANONICAL
	-DMESSAGE_4
)

#target_compile_options(app PRIVATE MESSAGE4)
target_compile_definitions(app PRIVATE MESSAGE4=1)

FILE(GLOB app_sources 
	src/*.c
	../../common/*.c
	../../../test_vectors/*.c)
#	../../edhoc-psk/base/uoscore-uedhoc-3.0.5-psk-v2/samples/common/*.c)
target_sources(app PRIVATE ${app_sources})


include(${ZEPHYR_BASE}/samples/net/common/common.cmake)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
