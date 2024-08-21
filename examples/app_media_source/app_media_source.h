#ifndef APP_MEDIA_SOURCE_H
#define APP_MEDIA_SOURCE_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "message_queue.h"
#include "peer_connection.h"

typedef enum AppMediaSourceRequestType
{
    APP_MEDIA_SOURCE_REQUEST_TYPE_NONE = 0,
    APP_MEDIA_SOURCE_REQUEST_TYPE_REMOTE_PEER_READY,
} AppMediaSourceRequestType_t;

typedef struct AppMediaSourceRequestMessage
{
    AppMediaSourceRequestType_t requestType;

    /* Decode the request message based on request type. */
    union
    {
        void * pContext; /* APP_MEDIA_SOURCE_REQUEST_TYPE_REMOTE_PEER_READY */
    } appMediaSourceRequestContent;
} AppMediaSourceRequestMessage_t;

typedef struct AppMediaSourceContext
{
    MessageQueueHandler_t requestQueue;
} AppMediaSourceContext_t;

typedef struct AppMediaSourcesContext
{
    AppMediaSourceContext_t videoContext;
    AppMediaSourceContext_t audioContext;
} AppMediaSourcesContext_t;

int32_t AppMediaSource_Init( AppMediaSourcesContext_t * pCtx );
int32_t AppMediaSource_ConstructVideoTransceiver( AppMediaSourcesContext_t * pCtx,
                                                  Transceiver_t * pVideoTranceiver );
int32_t AppMediaSource_ConstructAudioTransceiver( AppMediaSourcesContext_t * pCtx,
                                                  Transceiver_t * pAudioTranceiver );

#ifdef __cplusplus
}
#endif

#endif /* APP_MEDIA_SOURCE_H */
