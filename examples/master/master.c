#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "logging.h"
#include "demo_config.h"
#include "demo_data_types.h"
#include "signaling_controller.h"
#include "wifi_conf.h"
#include "lwip_netconf.h"

DemoContext_t demoContext;

static void webrtc_master_task( void *pParameter );

#define wifi_wait_time_ms 5000 //Here we wait 5 second to wiat the fast connect 
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
		}
	}
}


int32_t handleSignalingMessage( SignalingControllerReceiveEvent_t *pEvent, void *pUserContext )
{
    // uint8_t skipProcess = 0;
    // IceControllerResult_t iceControllerResult;
    // IceControllerCandidate_t candidate;

    // ( void ) pUserContext;

    // LogInfo( ( "Received Message from websocket server!" ) );
    // LogDebug( ( "Message Type: %x", pEvent->messageType ) );
    // LogDebug( ( "Sender ID: %.*s", ( int ) pEvent->remoteClientIdLength, pEvent->pRemoteClientId ) );
    // LogDebug( ( "Correlation ID: %.*s", ( int ) pEvent->correlationIdLength, pEvent->pCorrelationId ) );
    // LogDebug( ( "Message Length: %ld, Message:", pEvent->decodeMessageLength ) );
    // LogDebug( ( "%.*s", ( int ) pEvent->decodeMessageLength, pEvent->pDecodeMessage ) );

    // switch( pEvent->messageType )
    // {
    //     case SIGNALING_TYPE_MESSAGE_SDP_OFFER:
    //         skipProcess = addressSdpOffer( pEvent->pDecodeMessage, pEvent->decodeMessageLength, &demoContext );

    //         if( !skipProcess )
    //         {
    //             skipProcess = respondWithSdpAnswer( pEvent->pRemoteClientId, pEvent->remoteClientIdLength, &demoContext );
    //         }

    //         if( !skipProcess )
    //         {
    //             skipProcess = setRemoteDescription( &demoContext.iceControllerContext, &demoContext.sessionInformationSdpOffer, pEvent->pRemoteClientId, pEvent->remoteClientIdLength );
    //         }
    //         break;
    //     case SIGNALING_TYPE_MESSAGE_SDP_ANSWER:
    //         break;
    //     case SIGNALING_TYPE_MESSAGE_ICE_CANDIDATE:
    //         iceControllerResult = IceController_DeserializeIceCandidate( pEvent->pDecodeMessage, pEvent->decodeMessageLength, &candidate );
    //         if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
    //         {
    //             LogWarn( ( "IceController_DeserializeIceCandidate fail, result: %d, dropping ICE candidate.", iceControllerResult ) );
    //             skipProcess = 1;
    //         }

    //         if( !skipProcess )
    //         {
    //             iceControllerResult = IceController_SendRemoteCandidateRequest( &demoContext.iceControllerContext, pEvent->pRemoteClientId, pEvent->remoteClientIdLength, &candidate );
    //             if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
    //             {
    //                 LogWarn( ( "IceController_SendRemoteCandidateRequest fail, result: %d, dropping ICE candidate.", iceControllerResult ) );
    //                 skipProcess = 1;
    //             }
    //         }
    //         break;
    //     case SIGNALING_TYPE_MESSAGE_GO_AWAY:
    //         break;
    //     case SIGNALING_TYPE_MESSAGE_RECONNECT_ICE_SERVER:
    //         break;
    //     case SIGNALING_TYPE_MESSAGE_STATUS_RESPONSE:
    //         break;
    //     default:
    //         break;
    // }

    return 0;
}

void app_example(void)
{
    if( xTaskCreate( webrtc_master_task, ( (const char *)"webrtc_master_task" ), 20480, NULL, tskIDLE_PRIORITY + 1, NULL ) != pdPASS )
    {
		LogError( ("xTaskCreate(webrtc_master_task) failed") );
	}
}

void webrtc_master_task( void *pParameter )
{
    int ret = 0;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerCredential_t signalingControllerCred;

    (void) pParameter;

    LogDebug( ( "Start webrtc_master_demo_app_main." ) );

    wifi_common_init();

    memset( &demoContext, 0, sizeof( DemoContext_t ) );

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

    signalingControllerReturn = SignalingController_Init( &demoContext.signalingControllerContext, &signalingControllerCred, handleSignalingMessage, NULL );
    if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
    {
        LogError( ( "Fail to initialize signaling controller." ) );
        ret = -1;
    }

    // if( ret == 0 )
    // {
    //     /* Initialize Ice controller. */
    //     ret = initializeIceController( &demoContext );
    // }

    if( ret == 0 )
    {
        signalingControllerReturn = SignalingController_ConnectServers( &demoContext.signalingControllerContext );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to connect with signaling controller." ) );
            ret = -1;
        }
    }

    // if( ret == 0 )
    // {
    //     pthread_create( &threadIceController, NULL, executeIceController, &demoContext.iceControllerContext );
    // }

    // if( ret == 0 )
    // {
    //     /* This should never return unless exception happens. */
    //     signalingControllerReturn = SignalingController_ProcessLoop( &demoContext.signalingControllerContext );
    //     if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
    //     {
    //         LogError( ( "Fail to keep processing signaling controller." ) );
    //         ret = -1;
    //     }
    // }
}
