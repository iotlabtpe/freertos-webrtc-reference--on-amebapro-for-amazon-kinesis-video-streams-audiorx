#ifndef APP_MEDIA_SOURCE_H
#define APP_MEDIA_SOURCE_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "message_queue.h"
#include "peer_connection.h"
#include "app_media_source_port.h"

/* FreeRTOS includes. */
#include "semphr.h"

typedef struct AppMediaSourcesContext AppMediaSourcesContext_t;
typedef int32_t (* AppMediaSourceOnMediaSinkHook)( void * pCustom,
                                                   webrtc_frame_t * pFrame );

typedef struct AppMediaSourceContext
{
    /* Mutex to protect numReadyPeer because we might receive multiple ready/close message from different tasks. */
    SemaphoreHandle_t mediaMutex;
    MessageQueueHandler_t dataQueue;
    uint8_t numReadyPeer;
    TransceiverTrackKind_t trackKind;

    AppMediaSourcesContext_t * pSourcesContext;
} AppMediaSourceContext_t;

typedef struct AppMediaSourcesContext
{
    AppMediaSourceContext_t videoContext;
    AppMediaSourceContext_t audioContext;

    AppMediaSourceOnMediaSinkHook onMediaSinkHookFunc;
    void * pOnMediaSinkHookCustom;
} AppMediaSourcesContext_t;

int32_t AppMediaSource_Init( AppMediaSourcesContext_t * pCtx,
                             AppMediaSourceOnMediaSinkHook onMediaSinkHookFunc,
                             void * pOnMediaSinkHookCustom );
int32_t AppMediaSource_InitVideoTransceiver( AppMediaSourcesContext_t * pCtx,
                                             Transceiver_t * pVideoTranceiver );
int32_t AppMediaSource_InitAudioTransceiver( AppMediaSourcesContext_t * pCtx,
                                             Transceiver_t * pAudioTranceiver );

#ifdef __cplusplus
}
#endif

#endif /* APP_MEDIA_SOURCE_H */
