#ifndef HTTP_H
#define HTTP_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "core_http_helper.h"

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

typedef enum HttpResult
{
    HTTP_RESULT_OK = 0,
    HTTP_RESULT_FAIL,
    HTTP_RESULT_BAD_PARAMETER,
} HttpResult_t;

typedef struct HttpRequest
{
    char * pUrl;
    size_t urlLength;
    char * pBody;
    size_t bodyLength;

    uint8_t isFetchingCredential;
} HttpRequest_t;

typedef struct HttpResponse
{
    char * pBuffer;
    size_t bufferLength;
} HttpResponse_t;

HttpResult_t Http_Init( NetworkingCorehttpContext_t * pHttpCtx,
                        void * pCredential );
HttpResult_t Http_Send( NetworkingCorehttpContext_t * pHttpCtx,
                        HttpRequest_t * pRequest,
                        size_t timeoutMs,
                        HttpResponse_t * pResponse );
HttpResult_t Http_UpdateCredential( NetworkingCorehttpContext_t * pHttpCtx,
                                    void * pCredential );

#ifdef __cplusplus
}
#endif

#endif /* HTTP_H */
