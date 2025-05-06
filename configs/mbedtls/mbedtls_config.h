#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/* RTL_CRYPTO_FRAGMENT should be 16bytes-aligned */
#if defined(CONFIG_PLATFORM_8735B)
#define RTL_CRYPTO_FRAGMENT               65536 // 64k bytes
#else
#define RTL_CRYPTO_FRAGMENT               15360
#endif

#include "mbedtls/config_rsa.h"

#define MBEDTLS_HAVE_ASM

#undef MBEDTLS_DEBUG_C

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ERROR_C


#endif /* MBEDTLS_CUSTOM_CONFIG_H */
