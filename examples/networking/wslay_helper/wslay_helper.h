#ifndef WSLAY_HELPER_H
#define WSLAY_HELPER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "websocket.h"
#include "sigv4.h"
#include "transport_mbedtls.h"
#include "networking_utils.h"

#define NETWORKING_WEBSOCKET_BUFFER_LENGTH ( 10000 )
#define NETWORKING_META_BUFFER_LENGTH ( 4096 )

typedef enum NetworkingWslayResult
{
    NETWORKING_WSLAY_RESULT_OK = 0,
    NETWORKING_WSLAY_RESULT_BAD_PARAMETER,
    NETWORKING_WSLAY_RESULT_FAIL_CONNECT,
    NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF,
    NETWORKING_WSLAY_RESULT_FAIL_HTTP_INIT_REQUEST_HEADER,
    NETWORKING_WSLAY_RESULT_FAIL_GET_DATE,
    NETWORKING_WSLAY_RESULT_FAIL_HTTP_ADD,
    NETWORKING_WSLAY_RESULT_FAIL_HTTP_SEND,
    NETWORKING_WSLAY_RESULT_FAIL_HTTP_PARSE_RESPONSE,
    NETWORKING_WSLAY_RESULT_FAIL_BASE64_ENCODE,
    NETWORKING_WSLAY_RESULT_FAIL_VERIFY_ACCEPT_KEY,
    NETWORKING_WSLAY_RESULT_USER_AGENT_NAME_LENGTH_TOO_LONG,
    NETWORKING_WSLAY_RESULT_NO_HOST_IN_URL,
    NETWORKING_WSLAY_RESULT_NO_PATH_IN_URL,
    NETWORKING_WSLAY_RESULT_UNEXPECTED_WEBSOCKET_URL,
    NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL,
    NETWORKING_WSLAY_RESULT_URI_ENCODED_BUFFER_TOO_SMALL,
    NETWORKING_WSLAY_RESULT_AUTH_BUFFER_TOO_SMALL,
} NetworkingWslayResult_t;

typedef struct NetworkingWslayCredentials
{
    /* user-agent */
    char *pUserAgent;
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
} NetworkingWslayCredentials_t;

typedef enum NetworkingWslayHttpHeader
{
    NETWORKING_WSLAY_HTTP_HEADER_CONNECTION = 1,
    NETWORKING_WSLAY_HTTP_HEADER_UPGRADE = 2,
    NETWORKING_WSLAY_HTTP_HEADER_WEBSOCKET_ACCEPT = 4,
} NetworkingWslayHttpHeader_t;

typedef struct NetworkingWslayConnectResponseContext
{
    /* user-agent */
    char *pClientKey;
    size_t clientKeyLength;

    uint8_t headersParsed; //bitmap with NetworkingWslayHttpHeader_t value.
    uint16_t statusCode; //bitmap with NetworkingWslayHttpHeader_t value.
} NetworkingWslayConnectResponseContext_t;

typedef struct NetworkingWslayContext
{
    NetworkingWslayCredentials_t credentials;
    SigV4Credentials_t sigv4Credential;

    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t xTransportInterface;
    /* The network context for the transport layer interface. */
    NetworkContext_t xNetworkContext;
    TlsTransportParams_t xTlsTransportParams;
    NetworkCredentials_t xNetworkCredientials;

    /* Rx path: callback user to handle received message. */
    WebsocketMessageCallback_t websocketRxCallback;
    void * pWebsocketRxCallbackContext;
    char websocketTxBuffer[ NETWORKING_WEBSOCKET_BUFFER_LENGTH ];
    size_t websocketTxBufferLength;
    char websocketRxBuffer[ NETWORKING_WEBSOCKET_BUFFER_LENGTH ];
    size_t websocketRxBufferLength;
    char metaBuffer[ NETWORKING_META_BUFFER_LENGTH ];
    size_t metaBufferLength;
    char sigv4AuthBuffer[ NETWORKING_META_BUFFER_LENGTH ];
    size_t sigv4AuthBufferLength;
} NetworkingWslayContext_t;

#ifdef __cplusplus
}
#endif

#endif /* WSLAY_HELPER_H */
