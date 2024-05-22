#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "logging.h"
#include "demo_data_types.h"

DemoContext_t demoContext;

void app_example(void)
{
    LogDebug( ( "Start app_example." ) );
}

void webrtc_master_task( void *pParameter )
{
    (void) pParameter;
    LogDebug( ( "Start webrtc_master_demo_app_main." ) );
    // memset( &demoContext, 0, sizeof( DemoContext_t ) );

    // memset( &signalingControllerCred, 0, sizeof(SignalingControllerCredential_t) );
    // signalingControllerCred.pRegion = AWS_REGION;
    // signalingControllerCred.regionLength = strlen( AWS_REGION );
    // signalingControllerCred.pChannelName = AWS_KVS_CHANNEL_NAME;
    // signalingControllerCred.channelNameLength = strlen( AWS_KVS_CHANNEL_NAME );
    // signalingControllerCred.pUserAgentName = AWS_KVS_AGENT_NAME;
    // signalingControllerCred.userAgentNameLength = strlen(AWS_KVS_AGENT_NAME);
    // signalingControllerCred.pAccessKeyId = AWS_ACCESS_KEY_ID;
    // signalingControllerCred.accessKeyIdLength = strlen(AWS_ACCESS_KEY_ID);
    // signalingControllerCred.pSecretAccessKey = AWS_SECRET_ACCESS_KEY;
    // signalingControllerCred.secretAccessKeyLength = strlen(AWS_SECRET_ACCESS_KEY);
    // signalingControllerCred.pCaCertPath = AWS_CA_CERT_PATH;

    // signalingControllerReturn = SignalingController_Init( &demoContext.signalingControllerContext, &signalingControllerCred, handleSignalingMessage, NULL );
    // if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
    // {
    //     LogError( ( "Fail to initialize signaling controller." ) );
    //     ret = -1;
    // }

    // if( ret == 0 )
    // {
    //     /* Set the signal handler to release resource correctly. */
    //     signal( SIGINT, terminateHandler );

    //     /* Initialize Ice controller. */
    //     ret = initializeIceController( &demoContext );
    // }

    // if( ret == 0 )
    // {
    //     signalingControllerReturn = SignalingController_ConnectServers( &demoContext.signalingControllerContext );
    //     if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
    //     {
    //         LogError( ( "Fail to connect with signaling controller." ) );
    //         ret = -1;
    //     }
    // }

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
