#ifndef MODULE_KVS_WEBRTC_H
#define MODULE_KVS_WEBRTC_H

#include "mmf2_module.h"
#include "app_media_source_port.h"

#define CMD_KVS_WEBRTC_SET_PARAMS                               MM_MODULE_CMD( 0x00 )
#define CMD_KVS_WEBRTC_GET_PARAMS                               MM_MODULE_CMD( 0x01 )
#define CMD_KVS_WEBRTC_SET_APPLY                                MM_MODULE_CMD( 0x02 )
#define CMD_KVS_WEBRTC_STOP                                     MM_MODULE_CMD( 0x03 )
#define CMD_KVS_WEBRTC_START                                    MM_MODULE_CMD( 0x04 )
#define CMD_KVS_WEBRTC_REG_VIDEO_SEND_CALLBACK                  MM_MODULE_CMD( 0x05 )
#define CMD_KVS_WEBRTC_REG_VIDEO_SEND_CALLBACK_CUSTOM_CONTEXT   MM_MODULE_CMD( 0x06 )
#define CMD_KVS_WEBRTC_REG_AUDIO_SEND_CALLBACK                  MM_MODULE_CMD( 0x07 )
#define CMD_KVS_WEBRTC_REG_AUDIO_SEND_CALLBACK_CUSTOM_CONTEXT   MM_MODULE_CMD( 0x08 )

typedef struct MediaModuleContext {
    void * pParent;
    uint8_t mediaStart;

    OnFrameReadyToSend_t onVideoFrameReadyToSendFunc;
    void * pOnVideoFrameReadyToSendCustomContext;
    OnFrameReadyToSend_t onAudioFrameReadyToSendFunc;
    void * pOnAudioFrameReadyToSendCustomContext;
} MediaModuleContext_t;

#endif /* MODULE_KVS_WEBRTC_H */
