#include "logging.h"
#include "demo_config.h"
#include "ameba_pro2_media_port.h"
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

#include "avcodec.h"

#include "video_api.h"

#include "FreeRTOS.h"
#include "networking_utils.h"

/* used to monitor skb resource */
extern int skbbuf_used_num;
extern int skbdata_used_num;
extern int max_local_skb_num;
extern int max_skb_buf_num;

#define VIDEO_QCIF  0
#define VIDEO_CIF   1
#define VIDEO_WVGA  2
#define VIDEO_VGA   3
#define VIDEO_D1    4
#define VIDEO_HD    5
#define VIDEO_FHD   6
#define VIDEO_3M    7
#define VIDEO_5M    8
#define VIDEO_2K    9

/* Audio sending is always enabled, but audio receiving is not tested. */
#define MEDIA_PORT_ENABLE_AUDIO_RECV ( 0 )

/*****************************************************************************
* ISP channel : 0
* Video type  : H264/HEVC
*****************************************************************************/
#define MEDIA_PORT_V1_CHANNEL 0
#define MEDIA_PORT_V1_RESOLUTION VIDEO_HD
#define MEDIA_PORT_V1_FPS 30
#define MEDIA_PORT_V1_GOP 30
#define MEDIA_PORT_V1_BPS 512 * 1024
#define MEDIA_PORT_V1_RCMODE 2 // 1: CBR, 2: VBR

#if USE_H265
#define MEDIA_PORT_VIDEO_TYPE VIDEO_HEVC
#define MEDIA_PORT_VIDEO_CODEC AV_CODEC_ID_H265
#else
#define MEDIA_PORT_VIDEO_TYPE VIDEO_H264
#define MEDIA_PORT_VIDEO_CODEC AV_CODEC_ID_H264
#endif

#if MEDIA_PORT_V1_RESOLUTION == VIDEO_VGA
#define MEDIA_PORT_V1_WIDTH 640
#define MEDIA_PORT_V1_HEIGHT 480
#elif MEDIA_PORT_V1_RESOLUTION == VIDEO_HD
#define MEDIA_PORT_V1_WIDTH 1280
#define MEDIA_PORT_V1_HEIGHT 720
#elif MEDIA_PORT_V1_RESOLUTION == VIDEO_FHD
#define MEDIA_PORT_V1_WIDTH 1920
#define MEDIA_PORT_V1_HEIGHT 1080
#endif

static mm_context_t * pVideoContext = NULL;
static mm_context_t * pAudioContext = NULL;
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
#if MEDIA_PORT_ENABLE_AUDIO_RECV
static mm_context_t * pG711dContext = NULL;
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
static mm_context_t * pG711eContext = NULL;
#endif /* ( AUDIO_G711_MULAW || AUDIO_G711_ALAW ) */
#if ( AUDIO_OPUS )
static mm_context_t * pOpuscContext = NULL;
#if MEDIA_PORT_ENABLE_AUDIO_RECV
static mm_context_t * pOpusdContext = NULL;
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
#endif /* AUDIO_OPUS */
static mm_context_t * pWebrtcMmContext = NULL;

static mm_siso_t * pSisoAudioA1 = NULL;
static mm_siso_t * pSisoWebrtcA2 = NULL;
static mm_siso_t * pSisoAudioA2 = NULL;
static mm_miso_t * pMisoWebrtc = NULL;

static OnFrameReadyToSend_t gOnVideoFrameReadyToSendFunc;
static void * gpOnVideoFrameReadyToSendCustomContext;
static OnFrameReadyToSend_t gOnAudioFrameReadyToSendFunc;
static void * gpOnAudioFrameReadyToSendCustomContext;

static video_params_t videoParams = {
    .stream_id = MEDIA_PORT_V1_CHANNEL,
    .type = MEDIA_PORT_VIDEO_TYPE,
    .resolution = MEDIA_PORT_V1_RESOLUTION,
    .width = MEDIA_PORT_V1_WIDTH,
    .height = MEDIA_PORT_V1_HEIGHT,
    .bps = MEDIA_PORT_V1_BPS,
    .fps = MEDIA_PORT_V1_FPS,
    .gop = MEDIA_PORT_V1_GOP,
    .rc_mode = MEDIA_PORT_V1_RCMODE,
    .use_static_addr = 1
};

#if !USE_DEFAULT_AUDIO_SET
static audio_params_t audioParams = {
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
static g711_params_t g711eParams = {
    .codec_id = AV_CODEC_ID_PCMU,
    .buf_len = 2048,
    .mode = G711_ENCODE
};

#if MEDIA_PORT_ENABLE_AUDIO_RECV
static g711_params_t g711dParams = {
    .codec_id = AV_CODEC_ID_PCMU,
    .buf_len = 2048,
    .mode = G711_DECODE
};
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
#endif /* ( AUDIO_G711_MULAW || AUDIO_G711_ALAW ) */

#if ( AUDIO_OPUS )
static opusc_params_t opuscParams = {
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

#if MEDIA_PORT_ENABLE_AUDIO_RECV
static opusd_params_t opusdParams = {
    .sample_rate = 8000, // 16000
    .channel = 1,
    .bit_length = 16,         // 16 recommand
    .frame_size_in_msec = 10, // will not be uused
    .with_opus_enc = 1,       // enable semaphore if the application with opus encoder
    .opus_application = OPUS_APPLICATION_AUDIO
};
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
#endif /* AUDIO_OPUS */

static int HandleModuleFrameHook( void * p,
                                  void * input,
                                  void * output );
static int ControlModuleHook( void * p,
                              int cmd,
                              int arg );
static void * DestroyModuleHook( void * p );
static void * CreateModuleHook( void * parent );
static void * NewModuleItemHook( void * p );
static void * DeleteModuleItemHook( void * p,
                                    void * d );

mm_module_t webrtcMmModule = {
    .create = CreateModuleHook,
    .destroy = DestroyModuleHook,
    .control = ControlModuleHook,
    .handle = HandleModuleFrameHook,

    .new_item = NewModuleItemHook,
    .del_item = DeleteModuleItemHook,

    .output_type = MM_TYPE_ASINK, // output for audio sink
    .module_type = MM_TYPE_AVSINK, // module type is video algorithm
    .name = "KVS_WebRTC"
};

static int HandleModuleFrameHook( void * p,
                                  void * input,
                                  void * output )
{
    int ret = 0;
    MediaPortContext_t * pCtx = ( MediaPortContext_t * )p;
    MediaFrame_t frame;
    mm_queue_item_t * pInputItem = ( mm_queue_item_t * )input;

    if( pCtx->mediaStart != 0 )
    {
        do
        {
            /* wait for skb resource release */
            if( ( skbdata_used_num > ( max_skb_buf_num - 64 ) ) || ( skbbuf_used_num > ( max_local_skb_num - 64 ) ) )
            {
                ret = -1;
                break; //skip this frame and wait for skb resource release.
            }

            frame.size = pInputItem->size;
            frame.pData = ( uint8_t * )pvPortMalloc( frame.size );
            if( !frame.pData )
            {
                LogWarn( ( "fail to allocate memory for webrtc media frame" ) );
                ret = -1;
                break;
            }

            memcpy( frame.pData,
                    ( uint8_t * )pInputItem->data_addr,
                    frame.size );
            frame.freeData = 1;
            frame.timestampUs = NetworkingUtils_GetCurrentTimeUs( &pInputItem->timestamp );

            if( pInputItem->type == AV_CODEC_ID_H264 )
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
            else if( pInputItem->type == AV_CODEC_ID_OPUS )
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
            else if( pInputItem->type == AV_CODEC_ID_PCMU )
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
                LogWarn( ( "[KVS WebRTC module]: input type cannot be handled:%ld", pInputItem->type ) );
                vPortFree( frame.pData );
            }
        } while( pdFALSE );
    }

    return ret;
}

static int ControlModuleHook( void * p,
                              int cmd,
                              int arg )
{
    MediaPortContext_t * pCtx = ( MediaPortContext_t * )p;

    switch( cmd )
    {
        case CMD_KVS_WEBRTC_START:
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

static void * DestroyModuleHook( void * p )
{
    MediaPortContext_t * ctx = ( MediaPortContext_t * )p;
    if( ctx )
    {
        free( ctx );
    }
    return NULL;
}

static void * CreateModuleHook( void * parent )
{
    MediaPortContext_t * ctx = malloc( sizeof( MediaPortContext_t ) );
    if( !ctx )
    {
        return NULL;
    }
    memset( ctx,
            0,
            sizeof( MediaPortContext_t ) );
    ctx->pParent = parent;

    printf( "[KVS WebRTC module]: module created.\r\n" );

    return ctx;
}

static void * NewModuleItemHook( void * p )
{
    MediaPortContext_t * ctx = ( MediaPortContext_t * )p;
    ( void )ctx;

    // return (void *)malloc(WEBRTC_AUDIO_FRAME_SIZE * 2);
    return NULL;
}

static void * DeleteModuleItemHook( void * p,
                                    void * d )
{
    ( void )p;
    // if (d) {
    //  free(d);
    // }
    return NULL;
}

int32_t AppMediaSourcePort_Init( OnFrameReadyToSend_t onVideoFrameReadyToSendFunc,
                                 void * pOnVideoFrameReadyToSendCustomContext,
                                 OnFrameReadyToSend_t onAudioFrameReadyToSendFunc,
                                 void * pOnAudioFrameReadyToSendCustomContext )
{
    int32_t ret = 0;
    int voe_heap_size;

    pWebrtcMmContext = mm_module_open( &webrtcMmModule );
    if( pWebrtcMmContext )
    {
        gOnVideoFrameReadyToSendFunc = onVideoFrameReadyToSendFunc;
        gpOnVideoFrameReadyToSendCustomContext = pOnVideoFrameReadyToSendCustomContext;
        gOnAudioFrameReadyToSendFunc = onAudioFrameReadyToSendFunc;
        gpOnAudioFrameReadyToSendCustomContext = pOnAudioFrameReadyToSendCustomContext;

        mm_module_ctrl( pWebrtcMmContext,
                        MM_CMD_SET_QUEUE_LEN,
                        6 );
        mm_module_ctrl( pWebrtcMmContext,
                        MM_CMD_INIT_QUEUE_ITEMS,
                        MMQI_FLAG_STATIC );
        mm_module_ctrl( pWebrtcMmContext, CMD_KVS_WEBRTC_SET_APPLY, 0 );
    }
    else
    {
        LogError( ( "KVS open fail" ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        voe_heap_size = video_voe_presetting( 1, MEDIA_PORT_V1_WIDTH, MEDIA_PORT_V1_HEIGHT, MEDIA_PORT_V1_BPS, 0,
                                              0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0,
                                              0, 0, 0 );
        LogInfo( ( "voe heap size = %d", voe_heap_size ) );
    }

    if( ret == 0 )
    {
        pVideoContext = mm_module_open( &video_module );
        if( pVideoContext )
        {
            mm_module_ctrl( pVideoContext,
                            CMD_VIDEO_SET_PARAMS,
                            ( int )&videoParams );
            mm_module_ctrl( pVideoContext,
                            MM_CMD_SET_QUEUE_LEN,
                            MEDIA_PORT_V1_FPS * 3 );
            mm_module_ctrl( pVideoContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_DYNAMIC );
            mm_module_ctrl( pVideoContext,
                            CMD_VIDEO_APPLY,
                            MEDIA_PORT_V1_CHANNEL ); // start channel 0
        }
        else
        {
            LogError( ( "video open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        pAudioContext = mm_module_open( &audio_module );
        if( pAudioContext )
        {
#if !USE_DEFAULT_AUDIO_SET
            mm_module_ctrl( pAudioContext,
                            CMD_AUDIO_SET_PARAMS,
                            ( int )&audioParams );
#endif
            mm_module_ctrl( pAudioContext,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( pAudioContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( pAudioContext,
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
        pG711eContext = mm_module_open( &g711_module );
        if( pG711eContext )
        {
            mm_module_ctrl( pG711eContext,
                            CMD_G711_SET_PARAMS,
                            ( int )&g711eParams );
            mm_module_ctrl( pG711eContext,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( pG711eContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( pG711eContext,
                            CMD_G711_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "G711 open fail" ) );
            ret = -1;
        }
#elif AUDIO_OPUS
        pOpuscContext = mm_module_open( &opusc_module );
        if( pOpuscContext )
        {
            mm_module_ctrl( pOpuscContext,
                            CMD_OPUSC_SET_PARAMS,
                            ( int )&opuscParams );
            mm_module_ctrl( pOpuscContext,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( pOpuscContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( pOpuscContext,
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
        pSisoAudioA1 = siso_create();
        if( pSisoAudioA1 )
        {
            siso_ctrl( pSisoAudioA1,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )pAudioContext,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( pSisoAudioA1,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pG711eContext,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( pSisoAudioA1,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pOpuscContext,
                       0 );
            siso_ctrl( pSisoAudioA1,
                       MMIC_CMD_SET_STACKSIZE,
                       24 * 1024,
                       0 );
#endif
            siso_start( pSisoAudioA1 );
        }
        else
        {
            LogError( ( "pSisoAudioA1 open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        pMisoWebrtc = miso_create();
        if( pMisoWebrtc )
        {
#if defined( configENABLE_TRUSTZONE ) && ( configENABLE_TRUSTZONE == 1 )
            miso_ctrl( pMisoWebrtc,
                       MMIC_CMD_SET_SECURE_CONTEXT,
                       1,
                       0 );
#endif
            miso_ctrl( pMisoWebrtc,
                       MMIC_CMD_ADD_INPUT0,
                       ( uint32_t )pVideoContext,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            miso_ctrl( pMisoWebrtc,
                       MMIC_CMD_ADD_INPUT1,
                       ( uint32_t )pG711eContext,
                       0 );
#elif AUDIO_OPUS
            miso_ctrl( pMisoWebrtc,
                       MMIC_CMD_ADD_INPUT1,
                       ( uint32_t )pOpuscContext,
                       0 );
#endif
            miso_ctrl( pMisoWebrtc,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pWebrtcMmContext,
                       0 );
            miso_start( pMisoWebrtc );
        }
        else
        {
            LogError( ( "pMisoWebrtc open fail" ) );
            ret = -1;
        }
        LogInfo( ( "pMisoWebrtc started" ) );
    }

#if MEDIA_PORT_ENABLE_AUDIO_RECV
    if( ret == 0 )
    {
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
        pG711dContext = mm_module_open( &g711_module );
        if( pG711dContext )
        {
            mm_module_ctrl( pG711dContext,
                            CMD_G711_SET_PARAMS,
                            ( int )&g711dParams );
            mm_module_ctrl( pG711dContext,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( pG711dContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( pG711dContext,
                            CMD_G711_APPLY,
                            0 );
        }
        else
        {
            LogError( ( "G711 open fail" ) );
            ret = -1;
        }
#elif AUDIO_OPUS
        pOpusdContext = mm_module_open( &opusd_module );
        if( pOpusdContext )
        {
            mm_module_ctrl( pOpusdContext,
                            CMD_OPUSD_SET_PARAMS,
                            ( int )&opusdParams );
            mm_module_ctrl( pOpusdContext,
                            MM_CMD_SET_QUEUE_LEN,
                            6 );
            mm_module_ctrl( pOpusdContext,
                            MM_CMD_INIT_QUEUE_ITEMS,
                            MMQI_FLAG_STATIC );
            mm_module_ctrl( pOpusdContext,
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
        pSisoWebrtcA2 = siso_create();
        if( pSisoWebrtcA2 )
        {
            siso_ctrl( pSisoWebrtcA2,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )pWebrtcMmContext,
                       0 );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( pSisoWebrtcA2,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pG711dContext,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( pSisoWebrtcA2,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pOpusdContext,
                       0 );
            siso_ctrl( pSisoWebrtcA2,
                       MMIC_CMD_SET_STACKSIZE,
                       24 * 1024,
                       0 );
#endif
            siso_start( pSisoWebrtcA2 );
        }
        else
        {
            LogError( ( "pSisoWebrtcA2 open fail" ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        pSisoAudioA2 = siso_create();
        if( pSisoAudioA2 )
        {
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
            siso_ctrl( pSisoAudioA2,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )pG711dContext,
                       0 );
#elif AUDIO_OPUS
            siso_ctrl( pSisoAudioA2,
                       MMIC_CMD_ADD_INPUT,
                       ( uint32_t )pOpusdContext,
                       0 );
#endif
            siso_ctrl( pSisoAudioA2,
                       MMIC_CMD_ADD_OUTPUT,
                       ( uint32_t )pAudioContext,
                       0 );
            siso_start( pSisoAudioA2 );
        }
        else
        {
            LogError( ( "pSisoAudioA2 open fail" ) );
            ret = -1;
        }
    }
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */

    return ret;
}

void AppMediaSourcePort_Destroy( void )
{
    // Pause Linkers
    siso_pause( pSisoAudioA1 );
    miso_pause( pMisoWebrtc,
                MM_OUTPUT );
    siso_pause( pSisoWebrtcA2 );
    siso_pause( pSisoAudioA2 );

    // Stop modules
    mm_module_ctrl( pWebrtcMmContext,
                    CMD_KVS_WEBRTC_STOP,
                    0 );
    mm_module_ctrl( pVideoContext,
                    CMD_VIDEO_STREAM_STOP,
                    MEDIA_PORT_V1_CHANNEL );
    mm_module_ctrl( pAudioContext,
                    CMD_AUDIO_SET_TRX,
                    0 );

    // Delete linkers
    pSisoAudioA1 = siso_delete( pSisoAudioA1 );
    pMisoWebrtc = miso_delete( pMisoWebrtc );
    pSisoWebrtcA2 = siso_delete( pSisoWebrtcA2 );
    pSisoAudioA2 = siso_delete( pSisoAudioA2 );

    // Close modules
    pWebrtcMmContext = mm_module_close( pWebrtcMmContext );
    pVideoContext = mm_module_close( pVideoContext );
    pAudioContext = mm_module_close( pAudioContext );
#if ( AUDIO_G711_MULAW || AUDIO_G711_ALAW )
    pG711eContext = mm_module_close( pG711eContext );
#if MEDIA_PORT_ENABLE_AUDIO_RECV
    pG711dContext = mm_module_close( pG711dContext );
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
#elif AUDIO_OPUS
    pOpuscContext = mm_module_close( pOpuscContext );
#if MEDIA_PORT_ENABLE_AUDIO_RECV
    pOpusdContext = mm_module_close( pOpusdContext );
#endif /* MEDIA_PORT_ENABLE_AUDIO_RECV */
#endif

    // Video Deinit
    video_deinit();
}

int32_t AppMediaSourcePort_Start( void )
{
    int32_t ret = 0;

    mm_module_ctrl( pWebrtcMmContext,
                    CMD_KVS_WEBRTC_START,
                    0 );

    return ret;
}

void AppMediaSourcePort_Stop( void )
{
    mm_module_ctrl( pWebrtcMmContext,
                    CMD_KVS_WEBRTC_STOP,
                    0 );
}
