#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sys_api.h" // sys_backtrace_enable()
#include "sntp/sntp.h" // SNTP series APIs
#include "wifi_conf.h" // WiFi series APIs
#include "lwip_netconf.h" // LwIP_GetIP()

#include "logging.h"
#include "demo_config.h"
#include "demo_data_types.h"

#define IS_USERNAME_FOUND_BIT ( 1 << 0 )
#define IS_PASSWORD_FOUND_BIT ( 1 << 1 )
#define SET_REMOTE_INFO_USERNAME_FOUND( isFoundBit ) ( isFoundBit |= IS_USERNAME_FOUND_BIT )
#define SET_REMOTE_INFO_PASSWORD_FOUND( isFoundBit ) ( isFoundBit |= IS_PASSWORD_FOUND_BIT )
#define IS_REMOTE_INFO_ALL_FOUND( isFoundBit ) ( isFoundBit & IS_USERNAME_FOUND_BIT && isFoundBit & IS_PASSWORD_FOUND_BIT )

#define wifi_wait_time_ms 5000 //Here we wait 5 second to wiat the fast connect 

static void platform_init(void);
static void wifi_common_init(void);
static uint8_t IsUpdatedCurrentTime(void);
static uint8_t respondWithSdpAnswer( const char *pRemoteClientId, size_t remoteClientIdLength, DemoContext_t *pDemoContext );
static uint8_t searchUserNamePassWord( SdpControllerAttributes_t *pAttributes, size_t attributesCount,
                                       const char **ppRemoteUserName, size_t *pRemoteUserNameLength, const char **ppRemotePassword, size_t *pRemotePasswordLength );
static uint8_t getRemoteInfo( DemoSessionInformation_t *pSessionInformation, const char **ppRemoteUserName, size_t *pRemoteUserNameLength, const char **ppRemotePassword, size_t *pRemotePasswordLength );
static uint8_t setRemoteDescription( PeerConnectionContext_t *pPeerConnectionCtx, DemoSessionInformation_t *pSessionInformation, const char *pRemoteClientId, size_t remoteClientIdLength );
static int32_t handleSignalingMessage( SignalingControllerReceiveEvent_t *pEvent, void *pUserContext );
static int initializeApplication( DemoContext_t *pDemoContext );
static int initializePeerConnection( DemoContext_t *pDemoContext );
static void Master_Task( void *pParameter );

extern uint8_t prepareSdpAnswer( DemoSessionInformation_t *pSessionInDescriptionOffer, DemoSessionInformation_t *pSessionInDescriptionAnswer );
extern uint8_t serializeSdpMessage( DemoSessionInformation_t *pSessionInDescriptionAnswer, DemoContext_t *pDemoContext );
extern uint8_t addressSdpOffer( const char *pEventSdpOffer, size_t eventSdpOfferlength, DemoContext_t *pDemoContext );

DemoContext_t demoContext;

extern int crypto_init(void);
extern int platform_set_malloc_free( void * (*malloc_func)( size_t ), void (*free_func)( void * ) );
static void platform_init(void)
{
    /* mbedtls init */
	crypto_init();
	platform_set_malloc_free(calloc, free);

    /* Show backtrace if exception. */
    sys_backtrace_enable();

    /* Block until network ready. */
    wifi_common_init();
    
    /* Block until get time via SNTP. */
    sntp_init();
    while( IsUpdatedCurrentTime() )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
        LogInfo( ("waiting get epoch timer") );
    }
}

static void wifi_common_init(void)
{
	uint32_t wifi_wait_count = 0;

	while (!((wifi_get_join_status() == RTW_JOINSTATUS_SUCCESS) && (*(u32 *)LwIP_GetIP(0) != IP_ADDR_INVALID))) {
		vTaskDelay(10);
		wifi_wait_count+=10;
		if( wifi_wait_count >= wifi_wait_time_ms )
        {
			LogInfo( ("\r\nuse ATW0, ATW1, ATWC to make wifi connection\r\n") );
			LogInfo( ("wait for wifi connection...\r\n") );
            wifi_wait_count = 0;
		}
	}
}

static uint8_t IsUpdatedCurrentTime(void)
{
    uint8_t ret = 0;
	long long sec;
	long long usec;
	unsigned int tick;

    sntp_get_lasttime( &sec, &usec, &tick );
    if( sec > 10000000000000000ULL )
    {
        ret = 1;
    }

    return ret;
}

static uint8_t respondWithSdpAnswer( const char *pRemoteClientId, size_t remoteClientIdLength, DemoContext_t *pDemoContext )
{
    uint8_t skipProcess = 0;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerEventMessage_t eventMessage = {
        .event = SIGNALING_CONTROLLER_EVENT_SEND_WSS_MESSAGE,
        .onCompleteCallback = NULL,
        .pOnCompleteCallbackContext = NULL,
    };

    /* Prepare SDP answer and send it back to remote peer. */
    skipProcess = prepareSdpAnswer( &pDemoContext->sessionInformationSdpOffer, &pDemoContext->sessionInformationSdpAnswer );

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

static uint8_t searchUserNamePassWord( SdpControllerAttributes_t *pAttributes, size_t attributesCount,
                                       const char **ppRemoteUserName, size_t *pRemoteUserNameLength, const char **ppRemotePassword, size_t *pRemotePasswordLength )
{
    uint8_t isFound = 0;
    size_t i;

    for( i=0 ; i<attributesCount ; i++ )
    {
        if( pAttributes[i].attributeNameLength == strlen( "ice-ufrag" ) &&
            strncmp( pAttributes[i].pAttributeName, "ice-ufrag", pAttributes[i].attributeNameLength ) == 0 )
        {
            /* Found user name. */
            SET_REMOTE_INFO_USERNAME_FOUND( isFound );
            *ppRemoteUserName = pAttributes[i].pAttributeValue;
            *pRemoteUserNameLength = pAttributes[i].attributeValueLength;
        }
        else if( pAttributes[i].attributeNameLength == strlen( "ice-pwd" ) &&
                 strncmp( pAttributes[i].pAttributeName, "ice-pwd", pAttributes[i].attributeNameLength ) == 0 )
        {
            /* Found password. */
            SET_REMOTE_INFO_PASSWORD_FOUND( isFound );
            *ppRemotePassword = pAttributes[i].pAttributeValue;
            *pRemotePasswordLength = pAttributes[i].attributeValueLength;
        }
        else
        {
            continue;
        }

        if( IS_REMOTE_INFO_ALL_FOUND( isFound ) )
        {
            break;
        }
    }

    return isFound;
}

static uint8_t getRemoteInfo( DemoSessionInformation_t *pSessionInformation, const char **ppRemoteUserName, size_t *pRemoteUserNameLength, const char **ppRemotePassword, size_t *pRemotePasswordLength )
{
    uint8_t skipProcess = 0;
    SdpControllerSdpDescription_t *pSessionDescription = &pSessionInformation->sdpDescription;
    size_t i;
    uint8_t isFound;

    /* Assuming that the username & password in a single session description is same. */
    /* Search session attributes first. */
    isFound = searchUserNamePassWord( pSessionDescription->attributes, pSessionDescription->sessionAttributesCount,
                                      ppRemoteUserName, pRemoteUserNameLength,
                                      ppRemotePassword, pRemotePasswordLength );

    if( !IS_REMOTE_INFO_ALL_FOUND( isFound ) )
    {
        /* Search media attributes if not found in session attributes. */
        for( i=0 ; i<pSessionDescription->mediaCount ; i++ )
        {
            isFound = 0;
            isFound = searchUserNamePassWord( pSessionDescription->mediaDescriptions[i].attributes, pSessionDescription->mediaDescriptions[i].mediaAttributesCount,
                                              ppRemoteUserName, pRemoteUserNameLength,
                                              ppRemotePassword, pRemotePasswordLength );
            if( IS_REMOTE_INFO_ALL_FOUND( isFound ) )
            {
                break;
            }
        }
    }

    if( !IS_REMOTE_INFO_ALL_FOUND( isFound ) )
    {
        /* Can't find user name & pass word, drop this remote description. */
        LogWarn( ( "No remote username & password found in session description, drop this message" ) );
        skipProcess = 1;
    }

    return skipProcess;
}

static uint8_t setRemoteDescription( PeerConnectionContext_t *pPeerConnectionCtx, DemoSessionInformation_t *pSessionInformation, const char *pRemoteClientId, size_t remoteClientIdLength )
{
    uint8_t skipProcess = 0;
    PeerConnectionRemoteInfo_t remoteInfo;
    PeerConnectionResult_t peerConnectionResult;

    remoteInfo.pRemoteClientId = pRemoteClientId;
    remoteInfo.remoteClientIdLength = remoteClientIdLength;
    skipProcess = getRemoteInfo( pSessionInformation, &remoteInfo.pRemoteUserName, &remoteInfo.remoteUserNameLength, &remoteInfo.pRemotePassword, &remoteInfo.remotePasswordLength );

    if( skipProcess == 0 )
    {
        peerConnectionResult = PeerConnection_SetRemoteDescription( pPeerConnectionCtx, &remoteInfo );
        if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
        {
            LogError( ( "Fail to set remote description, result: %d", peerConnectionResult ) );
            skipProcess = 1;
        }
    }

    return skipProcess;
}

static int initializeApplication( DemoContext_t *pDemoContext )
{
    int ret = 0;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerCredential_t signalingControllerCred;

    if( pDemoContext == NULL )
    {
        LogError( ("Invalid input, demo context is NULL") );
        ret = -1;
    }

    if( ret == 0 )
    {
        memset( pDemoContext, 0, sizeof( DemoContext_t ) );
        
        /* Initialize Signaling controller. */
        memset( &signalingControllerCred, 0, sizeof(SignalingControllerCredential_t) );
        signalingControllerCred.pRegion = AWS_REGION;
        signalingControllerCred.regionLength = strlen( AWS_REGION );
        signalingControllerCred.pChannelName = AWS_KVS_CHANNEL_NAME;
        signalingControllerCred.channelNameLength = strlen( AWS_KVS_CHANNEL_NAME );
        signalingControllerCred.pUserAgentName = AWS_KVS_AGENT_NAME;
        signalingControllerCred.userAgentNameLength = strlen(AWS_KVS_AGENT_NAME);
        signalingControllerCred.pAccessKeyId = AWS_ACCESS_KEY_ID;
        signalingControllerCred.accessKeyIdLength = strlen(AWS_ACCESS_KEY_ID);
        signalingControllerCred.pSecretAccessKey = AWS_SECRET_ACCESS_KEY;
        signalingControllerCred.secretAccessKeyLength = strlen(AWS_SECRET_ACCESS_KEY);
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

static int initializePeerConnection( DemoContext_t *pDemoContext )
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

static int32_t handleSignalingMessage( SignalingControllerReceiveEvent_t *pEvent, void *pUserContext )
{
    uint8_t skipProcess = 0;
    PeerConnectionResult_t peerConnectionResult;

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
                skipProcess = respondWithSdpAnswer( pEvent->pRemoteClientId, pEvent->remoteClientIdLength, &demoContext );
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

static void Master_Task( void *pParameter )
{
    int ret = 0;
    SignalingControllerResult_t signalingControllerReturn;

    (void) pParameter;

    LogDebug( ( "Start webrtc_master_demo_app_main." ) );

    platform_init();

    ret = initializeApplication( &demoContext );

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

void app_example(void)
{
    int ret = 0;

    if( ret == 0 )
    {
        if( xTaskCreate( Master_Task, ( (const char *)"MasterTask" ), 20480, NULL, tskIDLE_PRIORITY + 2, NULL ) != pdPASS )
        {
            LogError( ("xTaskCreate(Master_Task) failed") );
            ret = -1;
        }
    }
}
