cmake_minimum_required(VERSION 3.6)

project(libsrtp)
set(libsrtp libsrtp)

# libsrtp library source files.
file(GLOB LIBSRTP_GLOB_SOURCES
          ${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/kernel/*.c
          ${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/math/*.c
          ${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/replay/*.c
          ${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/srtp/*.c )
set(LIBSRTP_SOURCES
          ${LIBSRTP_GLOB_SOURCES}
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/aes.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/aes_gcm_mbedtls.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/aes_icm_mbedtls.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/cipher.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/cipher_test_cases.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/cipher/null_cipher.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/auth_test_cases.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/auth.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/hmac.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/hmac_mbedtls.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/null_auth.c"
          "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/hash/sha1.c"
          )

# libsrtp library Public Include directories.
set( LIBSRTP_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/../examples/libsrtp"
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/include"
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/libsrtp/crypto/include" )

add_library(
     ${libsrtp} STATIC
     ${LIBSRTP_SOURCES}
)

list(
	APPEND libsrtp_flags
     HAVE_CONFIG_H
)

target_compile_definitions(${libsrtp} PRIVATE ${libsrtp_flags})

include( ${CMAKE_CURRENT_LIST_DIR}/../project/realtek_amebapro2_webrtc_application/GCC-RELEASE/includepath.cmake )
target_include_directories(
	${libsrtp}
	PUBLIC
     ${LIBSRTP_INCLUDE_PUBLIC_DIRS}
	${inc_path}
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33_NTZ/non_secure
)

### add linked library ###
list(
    APPEND app_example_lib
    libsrtp
)
