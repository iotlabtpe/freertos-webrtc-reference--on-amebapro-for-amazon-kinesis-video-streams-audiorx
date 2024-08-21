#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "FreeRTOS.h"
#include "task.h"
#include "app_media_source.h"

#define DEFAULT_TRANSCEIVER_ROLLING_BUFFER_DURACTION_SECOND ( 3 )

// Considering 4 Mbps for 720p (which is what our samples use). This is for H.264.
// The value could be different for other codecs.
#define DEFAULT_TRANSCEIVER_VIDEO_BIT_RATE ( 4 * 1024 * 1024 )

// For opus, the bitrate could be between 6 Kbps to 510 Kbps
#define DEFAULT_TRANSCEIVER_AUDIO_BIT_RATE ( 510 * 1024 )

#define DEFAULT_TRANSCEIVER_MEDIA_STREAM_ID "myKvsVideoStream"
#define DEFAULT_TRANSCEIVER_VIDEO_TRACK_ID "myVideoTrack"
#define DEFAULT_TRANSCEIVER_AUDIO_TRACK_ID "myAudioTrack"

#define DEMO_TRANSCEIVER_VIDEO_MESSAGE_QUEUE_NAME "/TxVideoMq"
#define DEMO_TRANSCEIVER_AUDIO_MESSAGE_QUEUE_NAME "/TxAudioMq"
#define DEMO_TRANSCEIVER_MAX_QUEUE_MSG_NUM ( 10 )

static void VideoTx_Task( void * pParameter );
static void AudioTx_Task( void * pParameter );

static void VideoTx_Task( void * pParameter )
{
    AppMediaSourceContext_t * pVideoContext = ( AppMediaSourceContext_t * )pParameter;
    MessageQueueResult_t retMessageQueue;
    AppMediaSourceRequestMessage_t requestMsg;
    size_t requestMsgLength;
    uint8_t skipProcess = 0;

    if( pVideoContext == NULL )
    {
        LogError( ( "Invalid input, pVideoContext: %p", pVideoContext ) );
        skipProcess = 1;
    }

    /* Handle event. */
    while( skipProcess == 0 )
    {
        requestMsgLength = sizeof( AppMediaSourceRequestMessage_t );
        retMessageQueue = MessageQueue_Recv( &pVideoContext->requestQueue,
                                             &requestMsg,
                                             &requestMsgLength );
        if( retMessageQueue == MESSAGE_QUEUE_RESULT_OK )
        {
            /* Received message, process it. */
            LogDebug( ( "Receive request type: %d", requestMsg.requestType ) );
            switch( requestMsg.requestType )
            {
                case APP_MEDIA_SOURCE_REQUEST_TYPE_REMOTE_PEER_READY:
                    break;
                default:
                    /* Unknown request, drop it. */
                    LogDebug( ( "Dropping unknown request %d", requestMsg.requestType ) );
                    break;
            }
        }
    }

    for( ;; )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
    }
}

static void AudioTx_Task( void * pParameter )
{
    AppMediaSourceContext_t * pAudioContext = ( AppMediaSourceContext_t * )pParameter;
    MessageQueueResult_t retMessageQueue;
    AppMediaSourceRequestMessage_t requestMsg;
    size_t requestMsgLength;
    uint8_t skipProcess = 0;

    if( pAudioContext == NULL )
    {
        LogError( ( "Invalid input, pAudioContext: %p", pAudioContext ) );
        skipProcess = 1;
    }

    /* Handle event. */
    while( skipProcess == 0 )
    {
        requestMsgLength = sizeof( AppMediaSourceRequestMessage_t );
        retMessageQueue = MessageQueue_Recv( &pAudioContext->requestQueue,
                                             &requestMsg,
                                             &requestMsgLength );
        if( retMessageQueue == MESSAGE_QUEUE_RESULT_OK )
        {
            /* Received message, process it. */
            LogDebug( ( "Receive request type: %d", requestMsg.requestType ) );
            switch( requestMsg.requestType )
            {
                case APP_MEDIA_SOURCE_REQUEST_TYPE_REMOTE_PEER_READY:
                    break;
                default:
                    /* Unknown request, drop it. */
                    LogDebug( ( "Dropping unknown request %d", requestMsg.requestType ) );
                    break;
            }
        }
    }

    for( ;; )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
    }
}

static int32_t OnPcEventRemotePeerReady( AppMediaSourceContext_t * pMediaSource )
{
    int32_t ret = 0;
    MessageQueueResult_t retMessageQueue;
    AppMediaSourceRequestMessage_t requestMsg;

    if( pMediaSource == NULL )
    {
        LogError( ( "Invalid input, pMediaSource: %p", pMediaSource ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        requestMsg.requestType = APP_MEDIA_SOURCE_REQUEST_TYPE_REMOTE_PEER_READY;

        retMessageQueue = MessageQueue_Send( &pMediaSource->requestQueue,
                                             &requestMsg,
                                             sizeof( AppMediaSourceRequestMessage_t ) );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to send message queue, error: %d", retMessageQueue ) );
            ret = -2;
        }
    }

    return ret;
}

static int32_t HandlePcEventCallback( void * pCustomContext,
                                      TransceiverCallbackEvent_t event,
                                      TransceiverCallbackContent_t * pEventMsg )
{
    int32_t ret = 0;
    AppMediaSourceContext_t * pMediaSource = ( AppMediaSourceContext_t * )pCustomContext;

    if( pMediaSource == NULL )
    {
        LogError( ( "Invalid input, pEventMsg: %p", pEventMsg ) );
        ret = -1;
    }

    switch( event )
    {
        case TRANSCEIVER_CB_EVENT_REMOTE_PEER_READY:
            ret = OnPcEventRemotePeerReady( pMediaSource );
            break;
        default:
            LogWarn( ( "Unknown event: 0x%x", event ) );
            break;
    }

    return ret;
}

static int32_t InitializeVideoSource( AppMediaSourceContext_t * pVideoSource )
{
    int32_t ret = 0;
    MessageQueueResult_t retMessageQueue;

    if( pVideoSource == NULL )
    {
        ret = -1;
        LogError( ( "Invalid input, pVideoSource: %p", pVideoSource ) );
    }

    if( ret == 0 )
    {
        retMessageQueue = MessageQueue_Create( &pVideoSource->requestQueue,
                                               DEMO_TRANSCEIVER_VIDEO_MESSAGE_QUEUE_NAME,
                                               sizeof( AppMediaSourceRequestMessage_t ),
                                               DEMO_TRANSCEIVER_MAX_QUEUE_MSG_NUM );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to open video transceiver message queue." ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        /* Create task for video Tx. */
        if( xTaskCreate( VideoTx_Task, ( ( const char * )"VideoTask" ), 2048, pVideoSource, tskIDLE_PRIORITY + 1, NULL ) != pdPASS )
        {
            LogError( ( "xTaskCreate(VideoTask) failed" ) );
            ret = -1;
        }
    }

    return ret;
}

static int32_t InitializeAudioSource( AppMediaSourceContext_t * pAudioSource )
{
    int32_t ret = 0;
    MessageQueueResult_t retMessageQueue;

    if( pAudioSource == NULL )
    {
        ret = -1;
        LogError( ( "Invalid input, pAudioSource: %p", pAudioSource ) );
    }

    if( ret == 0 )
    {
        retMessageQueue = MessageQueue_Create( &pAudioSource->requestQueue,
                                               DEMO_TRANSCEIVER_AUDIO_MESSAGE_QUEUE_NAME,
                                               sizeof( AppMediaSourceRequestMessage_t ),
                                               DEMO_TRANSCEIVER_MAX_QUEUE_MSG_NUM );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to open audio transceiver message queue." ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        /* Create task for audio Tx. */
        if( xTaskCreate( AudioTx_Task, ( ( const char * )"AudioTask" ), 2048, pAudioSource, tskIDLE_PRIORITY + 1, NULL ) != pdPASS )
        {
            LogError( ( "xTaskCreate(AudioTask) failed" ) );
            ret = -1;
        }
    }

    return ret;
}

int32_t AppMediaSource_Init( AppMediaSourcesContext_t * pCtx )
{
    int32_t ret = 0;

    ret = InitializeVideoSource( &pCtx->videoContext );

    if( ret == 0 )
    {
        ret = InitializeAudioSource( &pCtx->audioContext );
    }

    return ret;
}

int32_t AppMediaSource_ConstructVideoTransceiver( AppMediaSourcesContext_t * pCtx,
                                                  Transceiver_t * pVideoTranceiver )
{
    int32_t ret = 0;

    if( ( pCtx == NULL ) || ( pVideoTranceiver == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pVideoTranceiver: %p", pCtx, pVideoTranceiver ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        /* Initialize video transceiver. */
        pVideoTranceiver->trackKind = TRANSCEIVER_TRACK_KIND_VIDEO;
        pVideoTranceiver->direction = TRANSCEIVER_TRACK_DIRECTION_SENDRECV;
        TRANSCEIVER_ENABLE_CODEC( pVideoTranceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT );
        pVideoTranceiver->rollingbufferDurationSec = DEFAULT_TRANSCEIVER_ROLLING_BUFFER_DURACTION_SECOND;
        pVideoTranceiver->rollingbufferBitRate = DEFAULT_TRANSCEIVER_VIDEO_BIT_RATE;
        strncpy( pVideoTranceiver->streamId, DEFAULT_TRANSCEIVER_MEDIA_STREAM_ID, sizeof( pVideoTranceiver->streamId ) );
        pVideoTranceiver->streamIdLength = strlen( DEFAULT_TRANSCEIVER_MEDIA_STREAM_ID );
        strncpy( pVideoTranceiver->trackId, DEFAULT_TRANSCEIVER_VIDEO_TRACK_ID, sizeof( pVideoTranceiver->trackId ) );
        pVideoTranceiver->trackIdLength = strlen( DEFAULT_TRANSCEIVER_VIDEO_TRACK_ID );
        pVideoTranceiver->onPcEventCallbackFunc = HandlePcEventCallback;
        pVideoTranceiver->pOnPcEventCustomContext = &pCtx->videoContext;
    }

    return ret;
}

int32_t AppMediaSource_ConstructAudioTransceiver( AppMediaSourcesContext_t * pCtx,
                                                  Transceiver_t * pAudioTranceiver )
{
    int32_t ret = 0;

    if( ( pCtx == NULL ) || ( pAudioTranceiver == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pAudioTranceiver: %p", pCtx, pAudioTranceiver ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        /* Initialize audio transceiver. */
        pAudioTranceiver->trackKind = TRANSCEIVER_TRACK_KIND_AUDIO;
        pAudioTranceiver->direction = TRANSCEIVER_TRACK_DIRECTION_SENDRECV;
        TRANSCEIVER_ENABLE_CODEC( pAudioTranceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT );
        pAudioTranceiver->rollingbufferDurationSec = DEFAULT_TRANSCEIVER_ROLLING_BUFFER_DURACTION_SECOND;
        pAudioTranceiver->rollingbufferBitRate = DEFAULT_TRANSCEIVER_AUDIO_BIT_RATE;
        strncpy( pAudioTranceiver->streamId, DEFAULT_TRANSCEIVER_MEDIA_STREAM_ID, sizeof( pAudioTranceiver->streamId ) );
        pAudioTranceiver->streamIdLength = strlen( DEFAULT_TRANSCEIVER_MEDIA_STREAM_ID );
        strncpy( pAudioTranceiver->trackId, DEFAULT_TRANSCEIVER_AUDIO_TRACK_ID, sizeof( pAudioTranceiver->trackId ) );
        pAudioTranceiver->trackIdLength = strlen( DEFAULT_TRANSCEIVER_AUDIO_TRACK_ID );
        pAudioTranceiver->onPcEventCallbackFunc = HandlePcEventCallback;
        pAudioTranceiver->pOnPcEventCustomContext = &pCtx->audioContext;
    }

    return ret;
}
