/******************************************************************************
*
* Copyright(c) 2007 - 2021 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include "logging.h"
#include "module_kvs_webrtc.h"
#include "platform_opts.h"

#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "mmf2_miso.h"

#include "module_video.h"
#include "module_audio.h"
#include "module_g711.h"
#include "module_opusc.h"
#include "module_opusd.h"
#include "opus_defines.h"
#include "mmf2_pro2_video_config.h"

#include "avcodec.h"

#include "FreeRTOS.h"
#include "networking_utils.h"

/*****************************************************************************
* ISP channel : 0
* Video type  : H264/HEVC
*****************************************************************************/

#define V1_CHANNEL 0
#define V1_RESOLUTION VIDEO_HD
#define V1_FPS 30
#define V1_GOP 30
#define V1_BPS 1024 * 1024
#define V1_RCMODE 2 // 1: CBR, 2: VBR

#if USE_H265
#define VIDEO_TYPE VIDEO_HEVC
#define VIDEO_CODEC AV_CODEC_ID_H265
#else
#define VIDEO_TYPE VIDEO_H264
#define VIDEO_CODEC AV_CODEC_ID_H264
#endif

#if V1_RESOLUTION == VIDEO_VGA
#define V1_WIDTH 640
#define V1_HEIGHT 480
#elif V1_RESOLUTION == VIDEO_HD
#define V1_WIDTH 1280
#define V1_HEIGHT 720
#elif V1_RESOLUTION == VIDEO_FHD
#define V1_WIDTH 1920
#define V1_HEIGHT 1080
#endif

static mm_context_t * video_v1_ctx = NULL;
static mm_context_t * audio_ctx = NULL;
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
static mm_context_t * g711e_ctx = NULL;
static mm_context_t * g711d_ctx = NULL;
#endif
#if ( AUDIO_OPUS )
static mm_context_t * opusc_ctx = NULL;
static mm_context_t * opusd_ctx = NULL;
#endif
static mm_context_t * kvs_webrtc_v1_a1_ctx = NULL;

static mm_siso_t * siso_audio_a1 = NULL;
static mm_siso_t * siso_webrtc_a2 = NULL;
static mm_siso_t * siso_a2_audio = NULL;
static mm_miso_t * miso_kvs_webrtc_v1_a1 = NULL;

static OnFrameReadyToSend_t gOnVideoFrameReadyToSendFunc;
static void * gpOnVideoFrameReadyToSendCustomContext;
static OnFrameReadyToSend_t gOnAudioFrameReadyToSendFunc;
static void * gpOnAudioFrameReadyToSendCustomContext;

static video_params_t video_v1_params = {
    .stream_id = V1_CHANNEL,
    .type = VIDEO_TYPE,
    .resolution = V1_RESOLUTION,
    .width = V1_WIDTH,
    .height = V1_HEIGHT,
    .bps = V1_BPS,
    .fps = V1_FPS,
    .gop = V1_GOP,
    .rc_mode = V1_RCMODE,
    .use_static_addr = 1
};

#if !USE_DEFAULT_AUDIO_SET
static audio_params_t audio_params = {
    .sample_rate = ASR_8KHZ,
    .word_length = WL_16BIT,
    .mic_gain = MIC_0DB,
    .dmic_l_gain = DMIC_BOOST_24DB,
    .dmic_r_gain = DMIC_BOOST_24DB,
    .use_mic_type = USE_AUDIO_AMIC,
    .channel = 1,
    .mix_mode = 0,
    .enable_aec = 0
};
#endif

#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
static g711_params_t g711e_params = {
    .codec_id = AV_CODEC_ID_PCMU,
    .buf_len = 2048,
    .mode = G711_ENCODE
};

static g711_params_t g711d_params = {
    .codec_id = AV_CODEC_ID_PCMU,
    .buf_len = 2048,
    .mode = G711_DECODE
};
#endif

#if ( AUDIO_OPUS )
static opusc_params_t opusc_params = {
    .sample_rate = 8000, // 16000
    .channel = 1,
    .bit_length = 16,    // 16 recommand
    .complexity = 5,     // 0~10
    .bitrate = 25000,    // default 25000
    .use_framesize = 20, // 10 // needs to the same or bigger than AUDIO_DMA_PAGE_SIZE/(sample_rate/1000)/2 but less than 60
    .enable_vbr = 1,
    .vbr_constraint = 0,
    .packetLossPercentage = 0,
    .opus_application = OPUS_APPLICATION_AUDIO
};

static opusd_params_t opusd_only_params = {
    .sample_rate = 8000, // 16000
    .channel = 1,
    .bit_length = 16,         // 16 recommand
    .frame_size_in_msec = 10, // will not be uused
    .with_opus_enc = 1,       // enable semaphore if the application with opus encoder
    .opus_application = OPUS_APPLICATION_AUDIO
};
#endif

int kvs_webrtc_handle( void * p,
                       void * input,
                       void * output )
{
    kvs_webrtc_ctx_t * pCtx = ( kvs_webrtc_ctx_t * )p;
    webrtc_frame_t frame;
    mm_queue_item_t * input_item = ( mm_queue_item_t * )input;

    if( pCtx->mediaStart != 0 )
    {
        frame.size = input_item->size;
        frame.pData = ( uint8_t * )pvPortMalloc( frame.size );
        if( !frame.pData )
        {
            LogWarn( ( "fail to allocate memory for webrtc media frame" ) );
            return -1;
        }
        memcpy( frame.pData,
                ( uint8_t * )input_item->data_addr,
                frame.size );
        frame.freeData = 1;
        frame.timestampUs = NetworkingUtils_GetCurrentTimeUs( &input_item->timestamp );

        if( input_item->type == AV_CODEC_ID_H264 )
        {
            if( gOnVideoFrameReadyToSendFunc )
            {
                frame.trackKind = TRANSCEIVER_TRACK_KIND_VIDEO;
                ( void )gOnVideoFrameReadyToSendFunc( gpOnVideoFrameReadyToSendCustomContext,
                                                      &frame );
            }
            else
            {
                LogError( ( "No available ready to send callback function pointer." ) );
                vPortFree( frame.pData );
            }
        }
        else if( input_item->type == AV_CODEC_ID_OPUS )
        {
            LogInfo( ( "Opus packets, size: %lu", frame.size ) );
            if( gOnAudioFrameReadyToSendFunc )
            {
                frame.trackKind = TRANSCEIVER_TRACK_KIND_AUDIO;
                ( void )gOnAudioFrameReadyToSendFunc( gpOnAudioFrameReadyToSendCustomContext,
                                                      &frame );
            }
            else
            {
                LogError( ( "No available ready to send callback function pointer for audio." ) );
                vPortFree( frame.pData );
            }
        }
        else if( input_item->type == AV_CODEC_ID_PCMU )
        {
            if( gOnAudioFrameReadyToSendFunc )
            {
                frame.trackKind = TRANSCEIVER_TRACK_KIND_AUDIO;
                ( void )gOnAudioFrameReadyToSendFunc( gpOnAudioFrameReadyToSendCustomContext,
                                                      &frame );
            }
            else
            {
                LogError( ( "No available ready to send callback function pointer for audio." ) );
                vPortFree( frame.pData );
            }
        }
        else
        {
            LogWarn( ( "[KVS WebRTC module]: input type cannot be handled:%ld", input_item->type ) );
            vPortFree( frame.pData );
        }
    }

    return 0;
}

int kvs_webrtc_control( void * p,
                        int cmd,
                        int arg )
{
    kvs_webrtc_ctx_t * pCtx = ( kvs_webrtc_ctx_t * )p;

    switch( cmd )
    {
        case CMD_KVS_WEBRTC_SET_APPLY:
            /* If loopback is enabled, we don't need the camera to provide frames.
             * Instead, we loopback the received frames. */
#ifdef ENABLE_STREAMING_LOOPBACK
            pCtx->mediaStart = 0;
#else
            pCtx->mediaStart = 1;
#endif
            break;
        case CMD_KVS_WEBRTC_STOP:
            pCtx->mediaStart = 0;
            break;
    }
    return 0;
}

void *kvs_webrtc_destroy( void * p )
{
    kvs_webrtc_ctx_t * ctx = ( kvs_webrtc_ctx_t * )p;
    if( ctx )
    {
        free( ctx );
    }
    return NULL;
}

void *kvs_webrtc_create( void * parent )
{
    kvs_webrtc_ctx_t * ctx = malloc( sizeof( kvs_webrtc_ctx_t ) );
    if( !ctx )
    {
        return NULL;
    }
    memset( ctx,
            0,
            sizeof( kvs_webrtc_ctx_t ) );
    ctx->pParent = parent;

    printf( "[KVS WebRTC module]: module created.\r\n" );

    return ctx;
}

void *kvs_webrtc_new_item( void * p )
{
    kvs_webrtc_ctx_t * ctx = ( kvs_webrtc_ctx_t * )p;
    ( void )ctx;

    // return (void *)malloc(WEBRTC_AUDIO_FRAME_SIZE * 2);
    return NULL;
}

void *kvs_webrtc_del_item( void * p,
                           void * d )
{
    ( void )p;
    // if (d) {
    //  free(d);
    // }
    return NULL;
}

mm_module_t kvs_webrtc_module = {
    .create = kvs_webrtc_create,
    .destroy = kvs_webrtc_destroy,
    .control = kvs_webrtc_control,
    .handle = kvs_webrtc_handle,

    .new_item = kvs_webrtc_new_item,
    .del_item = kvs_webrtc_del_item,

    .output_type = MM_TYPE_NONE, // output for video sink
    .module_type = MM_TYPE_VDSP, // module type is video algorithm
    .name = "KVS_WebRTC"
};

int32_t AppMediaSourcePort_Init( OnFrameReadyToSend_t onVideoFrameReadyToSendFunc,
                                 void * pOnVideoFrameReadyToSendCustomContext,
                                 OnFrameReadyToSend_t onAudioFrameReadyToSendFunc,
                                 void * pOnAudioFrameReadyToSendCustomContext )
{
    int32_t ret = 0;
    int voe_heap_size;

    kvs_webrtc_v1_a1_ctx = mm_module_open( &kvs_webrtc_module );
    if( kvs_webrtc_v1_a1_ctx )
    {
        gOnVideoFrameReadyToSendFunc = onVideoFrameReadyToSendFunc;
        gpOnVideoFrameReadyToSendCustomContext = pOnVideoFrameReadyToSendCustomContext;
        gOnAudioFrameReadyToSendFunc = onAudioFrameReadyToSendFunc;
        gpOnAudioFrameReadyToSendCustomContext = pOnAudioFrameReadyToSendCustomContext;

        mm_module_ctrl( kvs_webrtc_v1_a1_ctx,
                        MM_CMD_SET_QUEUE_LEN,
                        6 );
        mm_module_ctrl( kvs_webrtc_v1_a1_ctx,
                        MM_CMD_INIT_QUEUE_ITEMS,
                        MMQI_FLAG_STATIC );
    }
    else
    {
        LogError( ( "KVS open fail" ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        voe_heap_size = video_voe_presetting( 1, V1_WIDTH, V1_HEIGHT, V1_BPS, 0,
                                              0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0,
                                              0, 0, 0 );
        LogInfo( ( "voe heap size = %d", voe_heap_size ) );
    }

    if( ret == 0 )
    {
        video_v1_ctx = mm_module_open( &video_module );
        if( video_v1_ctx )
        {
            mm_module_ctrl( video_v1_ctx,
                            CMD_VIDEO_SET_PARAMS,
                            ( int )&video_v1_params );
            mm_module_ctrl( video_v1_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            V1_FPS * 3 );
            mm_module_ctrl( video_v1_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_DYNAMIC );
            mm_module_ctrl( video_v1_ctx,
                            CMD_VIDEO_APPLY,
                            V1_CHANNEL );                              // start channel 0
        }
        else
        {
            LogError( ( "video open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        audio_ctx = mm_module_open( &audio_module );
        if( audio_ctx )
        {
#if !USE_DEFAULT_AUDIO_SET
            mm_module_ctrl( audio_ctx,
                            CMD_AUDIO_SET_PARAMS,
                            ( int )&audio_params );
#endif
            mm_module_ctrl( audio_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( audio_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( audio_ctx,
                            CMD_AUDIO_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "Audio open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
        g711e_ctx = mm_module_open( &g711_module );
        if( g711e_ctx )
        {
            mm_module_ctrl( g711e_ctx,
                            CMD_G711_SET_PARAMS,
                            ( int )&g711e_params );
            mm_module_ctrl( g711e_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( g711e_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( g711e_ctx,
                            CMD_G711_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "G711 open fail" ) );
            ret = -1;
        }
#elif AUDIO_OPUS
        opusc_ctx = mm_module_open( &opusc_module );
        if( opusc_ctx )
        {
            mm_module_ctrl( opusc_ctx,
                            CMD_OPUSC_SET_PARAMS,
                            ( int )&opusc_params );
            mm_module_ctrl( opusc_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( opusc_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( opusc_ctx,
                            CMD_OPUSC_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "OPUSC open fail" ) );
            ret = -1;
        }
#endif
    }

    if( ret == 0 )
    {
        siso_audio_a1 = siso_create();
        if( siso_audio_a1 )
        {
            siso_ctrl( siso_audio_a1,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )audio_ctx,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( siso_audio_a1,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )g711e_ctx,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( siso_audio_a1,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )opusc_ctx,
                       0 );
            siso_ctrl( siso_audio_a1,
                       MMIC_CMD_SET_STACKSIZE,
                       24 * 1024,
                       0 );
#endif
            siso_start( siso_audio_a1 );
        }
        else
        {
            LogError( ( "siso_audio_a1 open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        miso_kvs_webrtc_v1_a1 = miso_create();
        if( miso_kvs_webrtc_v1_a1 )
        {
#if defined( configENABLE_TRUSTZONE ) && ( configENABLE_TRUSTZONE == 1 )
            miso_ctrl( miso_kvs_webrtc_v1_a1,
                       MMIC_CMD_SET_SECURE_CONTEXT,
                       1,
                       0 );
#endif
            miso_ctrl( miso_kvs_webrtc_v1_a1,
                       MMIC_CMD_ADD_INPUT0,
                       ( uint32_t )video_v1_ctx,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            miso_ctrl( miso_kvs_webrtc_v1_a1,
                       MMIC_CMD_ADD_INPUT1,
                       ( uint32_t )g711e_ctx,
                       0 );
#elif AUDIO_OPUS
            miso_ctrl( miso_kvs_webrtc_v1_a1,
                       MMIC_CMD_ADD_INPUT1,
                       ( uint32_t )opusc_ctx,
                       0 );
#endif
            miso_ctrl( miso_kvs_webrtc_v1_a1,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )kvs_webrtc_v1_a1_ctx,
                       0 );
            miso_start( miso_kvs_webrtc_v1_a1 );
        }
        else
        {
            LogError( ( "miso_kvs_webrtc_v1_a1 open fail" ) );
            ret = -1;
        }
        LogInfo( ( "miso_kvs_webrtc_v1_a1 started" ) );
    }

    if( ret == 0 )
    {
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
        g711d_ctx = mm_module_open( &g711_module );
        if( g711d_ctx )
        {
            mm_module_ctrl( g711d_ctx,
                            CMD_G711_SET_PARAMS,
                            ( int )&g711d_params );
            mm_module_ctrl( g711d_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( g711d_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( g711d_ctx,
                            CMD_G711_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "G711 open fail" ) );
            ret = -1;
        }
#elif AUDIO_OPUS
        opusd_ctx = mm_module_open( &opusd_module );
        if( opusd_ctx )
        {
            mm_module_ctrl( opusd_ctx,
                            CMD_OPUSD_SET_PARAMS,
                            ( int )&opusd_only_params );
            mm_module_ctrl( opusd_ctx,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( opusd_ctx,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( opusd_ctx,
                            CMD_OPUSD_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "OPUSD open fail" ) );
            ret = -1;
        }
#endif
    }

    if( ret == 0 )
    {
        siso_webrtc_a2 = siso_create();
        if( siso_webrtc_a2 )
        {
            siso_ctrl( siso_webrtc_a2,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )kvs_webrtc_v1_a1_ctx,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( siso_webrtc_a2,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )g711d_ctx,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( siso_webrtc_a2,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )opusd_ctx,
                       0 );
            siso_ctrl( siso_webrtc_a2,
                       MMIC_CMD_SET_STACKSIZE,
                       24 * 1024,
                       0 );
#endif
            siso_start( siso_webrtc_a2 );
        }
        else
        {
            LogError( ( "siso_webrtc_a2 open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        siso_a2_audio = siso_create();
        if( siso_a2_audio )
        {
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( siso_a2_audio,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )g711d_ctx,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( siso_a2_audio,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )opusd_ctx,
                       0 );
#endif
            siso_ctrl( siso_a2_audio,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )audio_ctx,
                       0 );
            siso_start( siso_a2_audio );
        }
        else
        {
            LogError( ( "siso_a2_audio open fail" ) );
            ret = -1;
        }
    }

    return ret;
}

void AppMediaSourcePort_Destroy( void )
{
    // Pause Linkers
    siso_pause( siso_audio_a1 );
    miso_pause( miso_kvs_webrtc_v1_a1,
                MM_OUTPUT );
    siso_pause( siso_webrtc_a2 );
    siso_pause( siso_a2_audio );

    // Stop modules
    mm_module_ctrl( kvs_webrtc_v1_a1_ctx,
                    CMD_KVS_WEBRTC_STOP,
                    0 );
    mm_module_ctrl( video_v1_ctx,
                    CMD_VIDEO_STREAM_STOP,
                    V1_CHANNEL );
    mm_module_ctrl( audio_ctx,
                    CMD_AUDIO_SET_TRX,
                    0 );

    // Delete linkers
    siso_audio_a1 = siso_delete( siso_audio_a1 );
    miso_kvs_webrtc_v1_a1 = miso_delete( miso_kvs_webrtc_v1_a1 );
    siso_webrtc_a2 = siso_delete( siso_webrtc_a2 );
    siso_a2_audio = siso_delete( siso_a2_audio );

    // Close modules
    kvs_webrtc_v1_a1_ctx = mm_module_close( kvs_webrtc_v1_a1_ctx );
    video_v1_ctx = mm_module_close( video_v1_ctx );
    audio_ctx = mm_module_close( audio_ctx );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
    g711e_ctx = mm_module_close( g711e_ctx );
#if ENABLE_AUDIO_RECV
    g711d_ctx = mm_module_close( g711d_ctx );
#endif /* ENABLE_AUDIO_RECV */
#elif AUDIO_OPUS
    opusc_ctx = mm_module_close( opusc_ctx );
#if ENABLE_AUDIO_RECV
    opusd_ctx = mm_module_close( opusd_ctx );
#endif /* ENABLE_AUDIO_RECV */
#endif

    // Video Deinit
    video_deinit();
}

int32_t AppMediaSourcePort_Start( void )
{
    int32_t ret = 0;

    mm_module_ctrl( kvs_webrtc_v1_a1_ctx,
                    CMD_KVS_WEBRTC_SET_APPLY,
                    0 );

    return ret;
}

void AppMediaSourcePort_Stop( void )
{
    mm_module_ctrl( kvs_webrtc_v1_a1_ctx,
                    CMD_KVS_WEBRTC_STOP,
                    0 );
}
