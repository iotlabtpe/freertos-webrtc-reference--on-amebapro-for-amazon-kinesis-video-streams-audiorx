#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include "wslay_helper.h"

typedef enum WebsocketResult
{
    WEBSOCKET_RESULT_OK = 0,
    WEBSOCKET_RESULT_FAIL,
    WEBSOCKET_RESULT_BAD_PARAMETER,
} WebsocketResult_t;

typedef struct WebsocketServerInfo
{
    char * pUrl;
    size_t urlLength;
    uint16_t port;
} WebsocketServerInfo_t;

typedef WebsocketResult_t (* WebsocketMessageCallback_t)( char * pMessage,
                                                          size_t messageLength,
                                                          void * pUserContext );

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

    wslay_event_context_ptr wslayContext;

    TickType_t lastPingTick;
    int socketWakeUp;
    struct sockaddr_in socketWakeUpAddr;
} NetworkingWslayContext_t;

WebsocketResult_t Websocket_Init( NetworkingWslayContext_t * pWebsocketCtx,
                                  void * pCredential,
                                  WebsocketMessageCallback_t rxCallback,
                                  void * pRxCallbackContext );
WebsocketResult_t Websocket_Connect( NetworkingWslayContext_t * pWebsocketCtx,
                                     WebsocketServerInfo_t * pServerInfo );
WebsocketResult_t Websocket_Disconnect( NetworkingWslayContext_t * pWebsocketCtx );
WebsocketResult_t Websocket_Send( NetworkingWslayContext_t * pWebsocketCtx,
                                  char * pMessage,
                                  size_t messageLength );
WebsocketResult_t Websocket_Recv( NetworkingWslayContext_t * pWebsocketCtx );
WebsocketResult_t Websocket_Signal( NetworkingWslayContext_t * pWebsocketCtx );
WebsocketResult_t Websocket_UpdateCredential( NetworkingWslayContext_t * pWebsocketCtx,
                                              void * pCredential );

#ifdef __cplusplus
}
#endif

#endif /* WEBSOCKET_H */
