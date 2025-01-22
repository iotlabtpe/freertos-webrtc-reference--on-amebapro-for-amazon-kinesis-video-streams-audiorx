#ifndef CORE_HTTP_HELPER_H
#define CORE_HTTP_HELPER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "http.h"

#include "sigv4.h"
#include "networking_utils.h"

/* Transport interface implementation include header for TLS. */
#include "transport_mbedtls.h"


#define NETWORKING_COREHTTP_DEFAULT_REGION "us-west-2"

#define NETWORKING_COREHTTP_USER_AGENT_NAME_MAX_LENGTH ( 128 )
#define NETWORKING_COREHTTP_HOST_NAME_MAX_LENGTH ( 256 )
#define NETWORKING_COREHTTP_BUFFER_LENGTH ( 10000 )
#define NETWORKING_COREHTTP_SIGV4_METADATA_BUFFER_LENGTH ( 4096 )

typedef enum NetworkingCorehttpResult
{
    NETWORKING_COREHTTP_RESULT_OK = 0,
    NETWORKING_COREHTTP_RESULT_BAD_PARAMETER,
    NETWORKING_COREHTTP_RESULT_USER_AGENT_NAME_TOO_LONG,
    NETWORKING_COREHTTP_RESULT_FAIL_CONNECT,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_INIT_REQUEST_HEADER,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_HOST,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_USER_AGENT,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_DATE,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_CONTENT_TYPE,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_IOT_THING_NAME,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_AUTH,
    NETWORKING_COREHTTP_RESULT_FAIL_HTTP_SEND,
    NETWORKING_COREHTTP_RESULT_FAIL_SIGV4_GENERATE_AUTH,
    NETWORKING_COREHTTP_RESULT_FAIL_GET_DATE,
    NETWORKING_COREHTTP_RESULT_NO_HOST_IN_URL,
    NETWORKING_COREHTTP_RESULT_NO_PATH_IN_URL,
} NetworkingCorehttpResult_t;

typedef struct NetworkingCorehttpCredentials
{
    /* user-agent */
    char * pUserAgent;
    size_t userAgentLength;

    /* Region */
    char * pRegion;
    size_t regionLength;

    /* AKSK */
    char * pAccessKeyId;
    size_t accessKeyIdLength;
    char * pSecretAccessKey;
    size_t secretAccessKeyLength;

    /* CA Cert Path */
    char * pCaCertPath;

    /* Or CA PEM */
    const uint8_t * pRootCa;
    size_t rootCaSize;

    /* IoT thing credentials for role alias. */
    const uint8_t * pIotThingCert;
    size_t iotThingCertSize;
    const uint8_t * pIotThingPrivateKey;
    size_t iotThingPrivateKeySize;
    char * pIotThingName;
    size_t iotThingNameLength;
    char * pSessionToken;
    size_t sessionTokenLength;

    uint64_t expirationSeconds;
} NetworkingCorehttpCredentials_t;

typedef struct NetworkingCorehttpContext
{
    NetworkingCorehttpCredentials_t credentials;
    SigV4Credentials_t sigv4Credential;

    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t xTransportInterface;
    /* The network context for the transport layer interface. */
    NetworkContext_t xNetworkContext;
    TlsTransportParams_t xTlsTransportParams;
    NetworkCredentials_t xNetworkCredientials;

    char hostName[ NETWORKING_COREHTTP_HOST_NAME_MAX_LENGTH ];

    uint8_t requestBuffer[ NETWORKING_COREHTTP_BUFFER_LENGTH ];
    char sigv4AuthBuffer[ NETWORKING_COREHTTP_SIGV4_METADATA_BUFFER_LENGTH ];
    size_t sigv4AuthBufferLength;
} NetworkingCorehttpContext_t;

#ifdef __cplusplus
}
#endif

#endif /* CORE_HTTP_HELPER_H */
