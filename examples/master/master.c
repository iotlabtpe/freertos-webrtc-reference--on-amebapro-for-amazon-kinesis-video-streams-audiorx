#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "FreeRTOS.h"
#include "task.h"

#include "sys_api.h" // sys_backtrace_enable()
#include "sntp/sntp.h" // SNTP series APIs
#include "wifi_conf.h" // WiFi series APIs
#include "lwip_netconf.h" // LwIP_GetIP()
#include "srtp.h"

#include "logging.h"
#include "demo_config.h"
#include "demo_data_types.h"
#include "networking_utils.h"

#define DEFAULT_CERT_FINGERPRINT_PREFIX_LENGTH ( 8 ) // the length of "sha-256 "
#define wifi_wait_time_ms 5000 //Here we wait 5 second to wiat the fast connect

DemoContext_t demoContext;

static void Master_Task( void * pParameter );

static void platform_init( void );
static void wifi_common_init( void );
static uint8_t respondWithSdpAnswer( const char * pRemoteClientId,
                                     size_t remoteClientIdLength,
                                     DemoContext_t * pDemoContext,
                                     const char * pLocalFingerprint,
                                     size_t localFingerprintLength );
static uint8_t setRemoteDescription( PeerConnectionContext_t * pPeerConnectionCtx,
                                     DemoSessionInformation_t * pSessionInformation,
                                     const char * pRemoteClientId,
                                     size_t remoteClientIdLength );
static int32_t handleSignalingMessage( SignalingControllerReceiveEvent_t * pEvent,
                                       void * pUserContext );
static int initializeApplication( DemoContext_t * pDemoContext );
static int initializePeerConnection( DemoContext_t * pDemoContext );

extern uint8_t populateSdpContent( DemoSessionInformation_t * pRemoteSessionDescription,
                                   DemoSessionInformation_t * pLocalSessionDescription,
                                   PeerConnectionContext_t * pPeerConnectionContext,
                                   const char * pLocalFingerprint,
                                   size_t localFingerprintLength );
extern uint8_t serializeSdpMessage( DemoSessionInformation_t * pSessionInDescriptionAnswer,
                                    DemoContext_t * pDemoContext );
extern uint8_t addressSdpOffer( const char * pEventSdpOffer,
                                size_t eventSdpOfferlength,
                                DemoContext_t * pDemoContext );

extern int crypto_init( void );
extern int platform_set_malloc_free( void * ( *malloc_func )( size_t ),
                                     void ( * free_func )( void * ) );

static void platform_init( void )
{
    long long sec;
    /* mbedtls init */
    crypto_init();
    platform_set_malloc_free( ( void ( * ) )calloc, ( void ( * )( void * ) )free );

    /* Show backtrace if exception. */
    sys_backtrace_enable();

    /* Block until network ready. */
    wifi_common_init();

    /* Block until get time via SNTP. */
    sntp_init();
    while( ( sec = NetworkingUtils_GetCurrentTimeSec( NULL ) ) < 1000000000ULL )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
        LogInfo( ( "waiting get epoch timer" ) );
    }

    /* Seed random. */
    LogInfo( ( "srand seed: %lld", sec ) );
    srand( sec );

    /* init srtp library. */
    srtp_init();
}

static void wifi_common_init( void )
{
    uint32_t wifi_wait_count = 0;

    while( !( ( wifi_get_join_status() == RTW_JOINSTATUS_SUCCESS ) && ( *( u32 * )LwIP_GetIP( 0 ) != IP_ADDR_INVALID ) ) ) {
        vTaskDelay( 10 );
        wifi_wait_count += 10;
        if( wifi_wait_count >= wifi_wait_time_ms )
        {
            LogInfo( ( "\r\nuse ATW0, ATW1, ATWC to make wifi connection\r\n" ) );
            LogInfo( ( "wait for wifi connection...\r\n" ) );
            wifi_wait_count = 0;
        }
    }
}

static uint8_t respondWithSdpAnswer( const char * pRemoteClientId,
                                     size_t remoteClientIdLength,
                                     DemoContext_t * pDemoContext,
                                     const char * pLocalFingerprint,
                                     size_t localFingerprintLength )
{
    uint8_t skipProcess = 0;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerEventMessage_t eventMessage = {
        .event = SIGNALING_CONTROLLER_EVENT_SEND_WSS_MESSAGE,
        .onCompleteCallback = NULL,
        .pOnCompleteCallbackContext = NULL,
    };

    /* Prepare SDP answer and send it back to remote peer. */
    skipProcess = populateSdpContent( &pDemoContext->sessionInformationSdpOffer, &pDemoContext->sessionInformationSdpAnswer, &pDemoContext->peerConnectionContext, pLocalFingerprint, localFingerprintLength );

    if( !skipProcess )
    {
        skipProcess = serializeSdpMessage( &pDemoContext->sessionInformationSdpAnswer, pDemoContext );
    }

    if( !skipProcess )
    {
        eventMessage.eventContent.correlationIdLength = 0U;
        memset( eventMessage.eventContent.correlationId, 0, SIGNALING_CONTROLLER_CORRELATION_ID_MAX_LENGTH );
        eventMessage.eventContent.messageType = SIGNALING_TYPE_MESSAGE_SDP_ANSWER;
        eventMessage.eventContent.pDecodeMessage = pDemoContext->sessionInformationSdpAnswer.sdpBuffer;
        eventMessage.eventContent.decodeMessageLength = pDemoContext->sessionInformationSdpAnswer.sdpBufferLength;
        memcpy( eventMessage.eventContent.remoteClientId, pRemoteClientId, remoteClientIdLength );
        eventMessage.eventContent.remoteClientIdLength = remoteClientIdLength;

        signalingControllerReturn = SignalingController_SendMessage( &demoContext.signalingControllerContext, &eventMessage );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            skipProcess = 1;
            LogError( ( "Send signaling message fail, result: %d", signalingControllerReturn ) );
        }
    }

    return skipProcess;
}

static uint8_t setRemoteDescription( PeerConnectionContext_t * pPeerConnectionCtx,
                                     DemoSessionInformation_t * pSessionInformation,
                                     const char * pRemoteClientId,
                                     size_t remoteClientIdLength )
{
    uint8_t skipProcess = 0;
    PeerConnectionRemoteInfo_t remoteInfo;
    PeerConnectionResult_t peerConnectionResult;

    if( skipProcess == 0 )
    {
        remoteInfo.pRemoteClientId = pRemoteClientId;
        remoteInfo.remoteClientIdLength = remoteClientIdLength;
        remoteInfo.pRemoteUserName = pSessionInformation->sdpDescription.quickAccess.pIceUfrag;
        remoteInfo.remoteUserNameLength = pSessionInformation->sdpDescription.quickAccess.iceUfragLength;
        remoteInfo.pRemotePassword = pSessionInformation->sdpDescription.quickAccess.pIcePwd;
        remoteInfo.remotePasswordLength = pSessionInformation->sdpDescription.quickAccess.icePwdLength;
        remoteInfo.pRemoteCertFingerprint = pSessionInformation->sdpDescription.quickAccess.pFingerprint + DEFAULT_CERT_FINGERPRINT_PREFIX_LENGTH;
        remoteInfo.remoteCertFingerprintLength = pSessionInformation->sdpDescription.quickAccess.fingerprintLength - DEFAULT_CERT_FINGERPRINT_PREFIX_LENGTH;
        remoteInfo.twccId = pSessionInformation->sdpDescription.quickAccess.twccExtId;

        if( pSessionInformation->sdpDescription.quickAccess.isVideoCodecPayloadSet )
        {
            remoteInfo.isVideoCodecPayloadSet = 1;
            remoteInfo.videoCodecPayload = pSessionInformation->sdpDescription.quickAccess.videoCodecPayload;
        }
        else
        {
            remoteInfo.isVideoCodecPayloadSet = 0;
        }

        if( pSessionInformation->sdpDescription.quickAccess.isAudioCodecPayloadSet )
        {
            remoteInfo.isAudioCodecPayloadSet = 1;
            remoteInfo.audioCodecPayload = pSessionInformation->sdpDescription.quickAccess.audioCodecPayload;
        }
        else
        {
            remoteInfo.isAudioCodecPayloadSet = 0;
        }

        peerConnectionResult = PeerConnection_SetRemoteDescription( pPeerConnectionCtx, &remoteInfo );
        if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
        {
            LogError( ( "Fail to set remote description, result: %d", peerConnectionResult ) );
            skipProcess = 1;
        }
    }

    return skipProcess;
}

static int initializeApplication( DemoContext_t * pDemoContext )
{
    int ret = 0;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerCredential_t signalingControllerCred;

    if( pDemoContext == NULL )
    {
        LogError( ( "Invalid input, demo context is NULL" ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        memset( pDemoContext, 0, sizeof( DemoContext_t ) );

        /* Initialize Signaling controller. */
        memset( &signalingControllerCred, 0, sizeof( SignalingControllerCredential_t ) );
        signalingControllerCred.pRegion = AWS_REGION;
        signalingControllerCred.regionLength = strlen( AWS_REGION );
        signalingControllerCred.pChannelName = AWS_KVS_CHANNEL_NAME;
        signalingControllerCred.channelNameLength = strlen( AWS_KVS_CHANNEL_NAME );
        signalingControllerCred.pUserAgentName = AWS_KVS_AGENT_NAME;
        signalingControllerCred.userAgentNameLength = strlen( AWS_KVS_AGENT_NAME );
        signalingControllerCred.pAccessKeyId = AWS_ACCESS_KEY_ID;
        signalingControllerCred.accessKeyIdLength = strlen( AWS_ACCESS_KEY_ID );
        signalingControllerCred.pSecretAccessKey = AWS_SECRET_ACCESS_KEY;
        signalingControllerCred.secretAccessKeyLength = strlen( AWS_SECRET_ACCESS_KEY );
        signalingControllerCred.pCaCertPath = NULL;
        signalingControllerCred.pCaCertPem = AWS_CA_CERT_PEM;
        signalingControllerCred.caCertPemSize = sizeof( AWS_CA_CERT_PEM );

        signalingControllerReturn = SignalingController_Init( &pDemoContext->signalingControllerContext, &signalingControllerCred, handleSignalingMessage, NULL );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to initialize signaling controller." ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        /* Initialize Peer Connection. */
        ret = initializePeerConnection( pDemoContext );
    }

    return ret;
}

static int32_t OnMediaSinkHook( void * pCustom,
                                webrtc_frame_t * pFrame )
{
    int32_t ret = 0;
    DemoContext_t * pDemoContext = ( DemoContext_t * ) pCustom;
    PeerConnectionResult_t peerConnectionResult;
    Transceiver_t * pTransceiver = NULL;
    PeerConnectionFrame_t peerConnectionFrame;

    if( ( pDemoContext == NULL ) || ( pFrame == NULL ) )
    {
        LogError( ( "Invalid input, pCustom: %p, pFrame: %p", pCustom, pFrame ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        if( pFrame->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
        {
            ret = AppMediaSource_GetVideoTransceiver( &pDemoContext->appMediaSourcesContext, &pTransceiver );
        }
        else if( pFrame->trackKind == TRANSCEIVER_TRACK_KIND_AUDIO )
        {
            ret = AppMediaSource_GetAudioTransceiver( &pDemoContext->appMediaSourcesContext, &pTransceiver );
            ( void ) pTransceiver;
        }
        else
        {
            LogError( ( "Unknown track kind: %d", pFrame->trackKind ) );
            ret = -2;
        }
    }

    if( ret == 0 )
    {
        peerConnectionFrame.version = PEER_CONNECTION_FRAME_CURRENT_VERSION;
        peerConnectionFrame.presentationUs = pFrame->timestampUs;
        peerConnectionFrame.pData = pFrame->pData;
        peerConnectionFrame.dataLength = pFrame->size;
        peerConnectionResult = PeerConnection_WriteFrame( &pDemoContext->peerConnectionContext,
                                                          pTransceiver,
                                                          &peerConnectionFrame );
        if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
        {
            LogError( ( "Fail to write frame, result: %d", peerConnectionResult ) );
            ret = -3;
        }
    }

    return ret;
}

static int32_t InitializeAppMediaSource( DemoContext_t * pDemoContext )
{
    int32_t ret = 0;
    PeerConnectionResult_t peerConnectionResult;
    Transceiver_t * pTransceiver;

    if( pDemoContext == NULL )
    {
        LogError( ( "Invalid input, pDemoContext: %p", pDemoContext ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        ret = AppMediaSource_Init( &pDemoContext->appMediaSourcesContext, OnMediaSinkHook, pDemoContext );
    }

    /* Add video transceiver */
    if( ret == 0 )
    {
        ret = AppMediaSource_GetVideoTransceiver( &pDemoContext->appMediaSourcesContext, &pTransceiver );
        if( ret != 0 )
        {
            LogError( ( "Fail to get video transceiver." ) );
        }
        else
        {
            peerConnectionResult = PeerConnection_AddTransceiver( &pDemoContext->peerConnectionContext, pTransceiver );
            if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
            {
                LogError( ( "Fail to add video transceiver, result = %d.", peerConnectionResult ) );
                ret = -1;
            }
        }
    }

    /* Add audio transceiver */
    if( ret == 0 )
    {
        ret = AppMediaSource_GetAudioTransceiver( &pDemoContext->appMediaSourcesContext, &pTransceiver );
        if( ret != 0 )
        {
            LogError( ( "Fail to get audio transceiver." ) );
        }
        else
        {
            peerConnectionResult = PeerConnection_AddTransceiver( &pDemoContext->peerConnectionContext, pTransceiver );
            if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
            {
                LogError( ( "Fail to add audio transceiver, result = %d.", peerConnectionResult ) );
                ret = -1;
            }
        }
    }

    return ret;
}

static int initializePeerConnection( DemoContext_t * pDemoContext )
{
    int ret = 0;
    PeerConnectionResult_t peerConnectionResult;

    peerConnectionResult = PeerConnection_Init( &pDemoContext->peerConnectionContext, &pDemoContext->signalingControllerContext );
    if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
    {
        LogError( ( "Fail to initialize Peer Connection." ) );
        ret = -1;
    }

    return ret;
}

static uint8_t CreatePeerConnectionSession( PeerConnectionContext_t * pPeerConnectionContext,
                                            const char * pRemoteClientId,
                                            size_t remoteClientIdLength,
                                            const char ** ppLocalFingerprint,
                                            size_t * pLocalFingerprint )
{
    uint8_t skipProcess = 0;
    PeerConnectionResult_t peerConnectionResult;

    if( ( pPeerConnectionContext == NULL ) || ( pRemoteClientId == NULL ) )
    {
        LogError( ( "Invalid input, pPeerConnectionContext: %p, pRemoteClientId: %p", pPeerConnectionContext, pRemoteClientId ) );
        skipProcess = 1;
    }

    if( !skipProcess )
    {
        peerConnectionResult = PeerConnection_CreateSession( pPeerConnectionContext, pRemoteClientId, remoteClientIdLength, ppLocalFingerprint, pLocalFingerprint );
        if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
        {
            LogWarn( ( "PeerConnection_CreateSession fail, result: %d, dropping ICE candidate.", peerConnectionResult ) );
            skipProcess = 1;
        }
    }

    return skipProcess;
}

static int32_t handleSignalingMessage( SignalingControllerReceiveEvent_t * pEvent,
                                       void * pUserContext )
{
    uint8_t skipProcess = 0;
    PeerConnectionResult_t peerConnectionResult;
    const char * pLocalFingerprint = NULL;
    size_t localFingerprintLength = 0;

    ( void ) pUserContext;

    LogDebug( ( "Received Message from websocket server!" ) );
    LogDebug( ( "Message Type: %x", pEvent->messageType ) );
    LogDebug( ( "Sender ID: %.*s", ( int ) pEvent->remoteClientIdLength, pEvent->pRemoteClientId ) );
    LogDebug( ( "Correlation ID: %.*s", ( int ) pEvent->correlationIdLength, pEvent->pCorrelationId ) );
    LogDebug( ( "Message Length: %u, Message:", pEvent->decodeMessageLength ) );
    LogDebug( ( "%.*s", ( int ) pEvent->decodeMessageLength, pEvent->pDecodeMessage ) );

    switch( pEvent->messageType )
    {
        case SIGNALING_TYPE_MESSAGE_SDP_OFFER:
            skipProcess = addressSdpOffer( pEvent->pDecodeMessage, pEvent->decodeMessageLength, &demoContext );

            if( !skipProcess )
            {
                skipProcess = CreatePeerConnectionSession( &demoContext.peerConnectionContext, pEvent->pRemoteClientId, pEvent->remoteClientIdLength, &pLocalFingerprint, &localFingerprintLength );
            }

            if( !skipProcess )
            {
                skipProcess = respondWithSdpAnswer( pEvent->pRemoteClientId, pEvent->remoteClientIdLength, &demoContext, pLocalFingerprint, localFingerprintLength );
            }

            if( !skipProcess )
            {
                skipProcess = setRemoteDescription( &demoContext.peerConnectionContext, &demoContext.sessionInformationSdpOffer, pEvent->pRemoteClientId, pEvent->remoteClientIdLength );
            }
            break;
        case SIGNALING_TYPE_MESSAGE_SDP_ANSWER:
            break;
        case SIGNALING_TYPE_MESSAGE_ICE_CANDIDATE:
            peerConnectionResult = PeerConnection_AddRemoteCandidate( &demoContext.peerConnectionContext,
                                                                      pEvent->pRemoteClientId, pEvent->remoteClientIdLength,
                                                                      pEvent->pDecodeMessage, pEvent->decodeMessageLength );
            if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
            {
                LogWarn( ( "PeerConnection_AddRemoteCandidate fail, result: %d, dropping ICE candidate.", peerConnectionResult ) );
            }
            break;
        case SIGNALING_TYPE_MESSAGE_GO_AWAY:
            break;
        case SIGNALING_TYPE_MESSAGE_RECONNECT_ICE_SERVER:
            break;
        case SIGNALING_TYPE_MESSAGE_STATUS_RESPONSE:
            break;
        default:
            break;
    }

    return 0;
}

static void Master_Task( void * pParameter )
{
    int32_t ret = 0;
    SignalingControllerResult_t signalingControllerReturn;

    ( void ) pParameter;

    LogDebug( ( "Start webrtc_master_demo_app_main." ) );

    platform_init();

    ret = initializeApplication( &demoContext );

    if( ret == 0 )
    {
        ret = InitializeAppMediaSource( &demoContext );
    }

    if( ret == 0 )
    {
        signalingControllerReturn = SignalingController_ConnectServers( &demoContext.signalingControllerContext );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to connect with signaling controller." ) );
            ret = -1;
        }
    }

    if( ret == 0 )
    {
        /* This should never return unless exception happens. */
        signalingControllerReturn = SignalingController_ProcessLoop( &demoContext.signalingControllerContext );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to keep processing signaling controller." ) );
            ret = -1;
        }
    }

    for( ;; )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
    }
}

void app_example( void )
{
    int ret = 0;

    if( ret == 0 )
    {
        if( xTaskCreate( Master_Task, ( ( const char * )"MasterTask" ), 20480, NULL, tskIDLE_PRIORITY + 2, NULL ) != pdPASS )
        {
            LogError( ( "xTaskCreate(Master_Task) failed" ) );
            ret = -1;
        }
    }
}
