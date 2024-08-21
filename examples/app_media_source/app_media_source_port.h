#ifndef APP_MEDIA_SOURCE_PORT_H
#define APP_MEDIA_SOURCE_PORT_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

typedef struct {
    uint8_t * pData;
    uint32_t size;
    uint32_t timestamp;
    uint32_t type;
    uint8_t freeData;  /* indicate user need to free pData after using it */
} webrtc_frame_t;

typedef int32_t (* OnFrameReadyToSend_t)( void * pCtx,
                                          webrtc_frame_t * pFrame );

int32_t AppMediaSourcePort_Init( OnFrameReadyToSend_t onVideoFrameReadyToSendFunc,
                                 void * pOnVideoFrameReadyToSendCustomContext,
                                 OnFrameReadyToSend_t onAudioFrameReadyToSendFunc,
                                 void * pOnAudioFrameReadyToSendCustomContext );
int32_t AppMediaSourcePort_Start( void );
void AppMediaSourcePort_Stop( void );
void AppMediaSourcePort_Destroy( void );

#ifdef __cplusplus
}
#endif

#endif /* APP_MEDIA_SOURCE_PORT_H */
