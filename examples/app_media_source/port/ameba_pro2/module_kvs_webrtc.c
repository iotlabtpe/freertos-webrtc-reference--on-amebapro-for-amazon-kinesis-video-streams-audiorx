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

#define USE_H265 0

#if USE_H265
#define VIDEO_TYPE VIDEO_HEVC
#define VIDEO_CODEC AV_CODEC_ID_H265
#else
#define VIDEO_TYPE VIDEO_H264
#define VIDEO_CODEC AV_CODEC_ID_H264
#endif

#if V1_RESOLUTION == VIDEO_VGA
#define V1_WIDTH    640
#define V1_HEIGHT   480
#elif V1_RESOLUTION == VIDEO_HD
#define V1_WIDTH    1280
#define V1_HEIGHT   720
#elif V1_RESOLUTION == VIDEO_FHD
#define V1_WIDTH    1920
#define V1_HEIGHT   1080
#endif

static mm_context_t * video_v1_ctx = NULL;
static mm_context_t * kvs_webrtc_v1_a1_ctx = NULL;
static mm_siso_t * siso_video_kvs_v1 = NULL;
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
        frame.pData = ( uint8_t * ) pvPortMalloc( frame.size );
        if( !frame.pData )
        {
            LogWarn( ( "fail to allocate memory for webrtc media frame" ) );
            return -1;
        }
        memcpy( frame.pData, ( uint8_t * )input_item->data_addr, frame.size );
        frame.freeData = 1;
        frame.timestampUs = NetworkingUtils_GetCurrentTimeUs( &input_item->timestamp );

        if( input_item->type == AV_CODEC_ID_H264 )
        {
            if( gOnVideoFrameReadyToSendFunc )
            {
                frame.trackKind = TRANSCEIVER_TRACK_KIND_VIDEO;
                ( void ) gOnVideoFrameReadyToSendFunc( gpOnVideoFrameReadyToSendCustomContext, &frame );
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
            pCtx->mediaStart = 1;
            break;
        case CMD_KVS_WEBRTC_STOP:
            pCtx->mediaStart = 0;
            break;
    }
    return 0;
}

void * kvs_webrtc_destroy( void * p )
{
    kvs_webrtc_ctx_t * ctx = ( kvs_webrtc_ctx_t * )p;
    if( ctx )
    {
        free( ctx );
    }
    return NULL;
}


void * kvs_webrtc_create( void * parent )
{
    kvs_webrtc_ctx_t * ctx = malloc( sizeof( kvs_webrtc_ctx_t ) );
    if( !ctx )
    {
        return NULL;
    }
    memset( ctx, 0, sizeof( kvs_webrtc_ctx_t ) );
    ctx->pParent = parent;

    printf( "[KVS WebRTC module]: module created.\r\n" );

    return ctx;
}


void * kvs_webrtc_new_item( void * p )
{
    kvs_webrtc_ctx_t * ctx = ( kvs_webrtc_ctx_t * )p;
    ( void )ctx;

    // return (void *)malloc(WEBRTC_AUDIO_FRAME_SIZE * 2);
    return NULL;
}


void * kvs_webrtc_del_item( void * p,
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

    .output_type = MM_TYPE_NONE,        // output for video sink
    .module_type = MM_TYPE_VDSP,        // module type is video algorithm
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

        mm_module_ctrl( kvs_webrtc_v1_a1_ctx, MM_CMD_SET_QUEUE_LEN, 6 );
        mm_module_ctrl( kvs_webrtc_v1_a1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC );
    }
    else {
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
            mm_module_ctrl( video_v1_ctx, CMD_VIDEO_SET_PARAMS, ( int )&video_v1_params );
            mm_module_ctrl( video_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_FPS * 3 );
            mm_module_ctrl( video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC );
            mm_module_ctrl( video_v1_ctx, CMD_VIDEO_APPLY, V1_CHANNEL );  // start channel 0
        }
        else {
            LogError( ( "video open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        siso_video_kvs_v1 = siso_create();
        if( siso_video_kvs_v1 )
        {
    #if defined( configENABLE_TRUSTZONE ) && ( configENABLE_TRUSTZONE == 1 )
            siso_ctrl( siso_video_kvs_v1, MMIC_CMD_SET_SECURE_CONTEXT, 1, 0 );
    #endif
            siso_ctrl( siso_video_kvs_v1, MMIC_CMD_ADD_INPUT, ( uint32_t )video_v1_ctx, 0 );
            siso_ctrl( siso_video_kvs_v1, MMIC_CMD_ADD_OUTPUT, ( uint32_t )kvs_webrtc_v1_a1_ctx, 0 );
            siso_start( siso_video_kvs_v1 );
        }
        else {
            LogError( ( "siso2 open fail" ) );
            ret = -1;
        }
    }

    return ret;
}

void AppMediaSourcePort_Destroy( void )
{
    //Pause Linker
    siso_pause( siso_video_kvs_v1 );

    //Stop module
    mm_module_ctrl( kvs_webrtc_v1_a1_ctx, CMD_KVS_WEBRTC_STOP, 0 );
    mm_module_ctrl( video_v1_ctx, CMD_VIDEO_STREAM_STOP, V1_CHANNEL );

    //Delete linker
    siso_delete( siso_video_kvs_v1 );

    //Close module
    mm_module_close( video_v1_ctx );
    mm_module_close( kvs_webrtc_v1_a1_ctx );

    //Video Deinit
    video_deinit();
}

int32_t AppMediaSourcePort_Start( void )
{
    int32_t ret = 0;

    mm_module_ctrl( kvs_webrtc_v1_a1_ctx, CMD_KVS_WEBRTC_SET_APPLY, 0 );

    return ret;
}

void AppMediaSourcePort_Stop( void )
{
    mm_module_ctrl( kvs_webrtc_v1_a1_ctx, CMD_KVS_WEBRTC_STOP, 0 );
}
