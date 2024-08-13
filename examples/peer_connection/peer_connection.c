#include <stdlib.h>
#include "FreeRTOS.h"
#include "task.h"
#include "logging.h"
#include "peer_connection.h"

#define PeerConnectionIceTaskName "IceTask"
#define PeerConnectionIceSockListenerTaskName "IceSockLnrTask" // For Ice controller to monitor socket Rx path

extern void IceControllerSocketListener_Task( void * pParameter );

static void IceController_Task( void * pParameter )
{
    IceControllerContext_t * pIceControllerContext = ( IceControllerContext_t * ) pParameter;

    for( ;; )
    {
        ( void ) IceController_ProcessLoop( pIceControllerContext );
    }
}

static PeerConnectionResult_t InitializeIceController( PeerConnectionContext_t * pCtx,
                                                       SignalingControllerContext_t * pSignalingControllerContext )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( ( pCtx == NULL ) || ( pSignalingControllerContext == NULL ) )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_Init( &pCtx->iceControllerContext, pSignalingControllerContext );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to initialize Ice Controller." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_INIT;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( xTaskCreate( IceController_Task,
                         PeerConnectionIceTaskName,
                         10240,
                         &pCtx->iceControllerContext,
                         tskIDLE_PRIORITY + 2,
                         NULL ) != pdPASS )
        {
            LogError( ( "xTaskCreate(%s) failed", PeerConnectionIceTaskName ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_CONTROLLER;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( xTaskCreate( IceControllerSocketListener_Task,
                         PeerConnectionIceSockListenerTaskName,
                         1024,
                         &pCtx->iceControllerContext,
                         tskIDLE_PRIORITY + 1,
                         NULL ) != pdPASS )
        {
            LogError( ( "xTaskCreate(%s) failed", PeerConnectionIceSockListenerTaskName ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_SOCK_LISTENER;
        }
    }

    return ret;
}

static PeerConnectionResult_t DestroyIceController( PeerConnectionContext_t * pCtx )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( pCtx == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_Destroy( &pCtx->iceControllerContext );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to destroy Ice Controller." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESTROY;
        }
    }

    return ret;
}

static Transceiver_t * AllocateFreeTransceiver( PeerConnectionContext_t * pCtx )
{
    Transceiver_t * pReturn = NULL;

    if( pCtx && ( pCtx->transceiverCount < PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ) )
    {
        pReturn = &pCtx->transceivers[ pCtx->transceiverCount++ ];
    }

    return pReturn;
}

PeerConnectionResult_t PeerConnection_Init( PeerConnectionContext_t * pCtx,
                                            SignalingControllerContext_t * pSignalingControllerContext )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( ( pCtx == NULL ) || ( pSignalingControllerContext == NULL ) )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( pCtx, 0, sizeof( PeerConnectionContext_t ) );

        /* Initialize other modules. */
        ret = InitializeIceController( pCtx, pSignalingControllerContext );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_Destroy( PeerConnectionContext_t * pCtx )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( pCtx == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        /* Deinitialize Ice Controller. */
        ret = DestroyIceController( pCtx );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_SetRemoteDescription( PeerConnectionContext_t * pCtx,
                                                            const PeerConnectionRemoteInfo_t * pRemoteInfo )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( ( pCtx == NULL ) || ( pRemoteInfo == NULL ) ||
        ( pRemoteInfo->pRemoteClientId == NULL ) ||
        ( pRemoteInfo->pRemotePassword == NULL ) ||
        ( pRemoteInfo->pRemoteUserName == NULL ) ||
        ( pRemoteInfo->pRemoteCertFingerprint == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pRemoteInfo: %p", pCtx, pRemoteInfo ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_SetRemoteDescription( &pCtx->iceControllerContext,
                                                                  pRemoteInfo->pRemoteClientId, pRemoteInfo->remoteClientIdLength,
                                                                  pRemoteInfo->pRemoteUserName, pRemoteInfo->remoteUserNameLength,
                                                                  pRemoteInfo->pRemotePassword, pRemoteInfo->remotePasswordLength,
                                                                  pRemoteInfo->pRemoteCertFingerprint, pRemoteInfo->remoteCertFingerprintLength );
        if( iceControllerResult != 0 )
        {
            LogError( ( "Fail to set remote description in Ice Controller, result: %d", iceControllerResult ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SET_REMOTE_DESCRIPTION;
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_AddRemoteCandidate( PeerConnectionContext_t * pCtx,
                                                          const char * pRemoteClientId,
                                                          size_t remoteClientIdLength,
                                                          const char * pDecodeMessage,
                                                          size_t decodeMessageLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;
    IceControllerCandidate_t candidate;

    if( ( pCtx == NULL ) ||
        ( pRemoteClientId == NULL ) ||
        ( pDecodeMessage == NULL ) )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_DeserializeIceCandidate( pDecodeMessage, decodeMessageLength, &candidate );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogWarn( ( "IceController_DeserializeIceCandidate fail, result: %d, dropping ICE candidate.", iceControllerResult ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESERIALIZE_CANDIDATE;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_SendRemoteCandidateRequest( &pCtx->iceControllerContext, pRemoteClientId, remoteClientIdLength, &candidate );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogWarn( ( "IceController_SendRemoteCandidateRequest fail, result: %d, dropping ICE candidate.", iceControllerResult ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_REMOTE_CANDIDATE;
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_AddTransceiver( PeerConnectionContext_t * pCtx,
                                                      const Transceiver_t transceiver )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    Transceiver_t * pTargetTransceiver;

    if( pCtx == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pTargetTransceiver = AllocateFreeTransceiver( pCtx );
        if( pTargetTransceiver == NULL )
        {
            LogWarn( ( "No space to add transceiver" ) );
            ret = PEER_CONNECTION_RESULT_NO_FREE_TRANSCEIVER;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memcpy( pTargetTransceiver, &transceiver, sizeof( Transceiver_t ) );
        pTargetTransceiver->ssrc = ( uint32_t ) rand();
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_GetTransceivers( PeerConnectionContext_t * pCtx,
                                                       const Transceiver_t ** ppTransceivers,
                                                       size_t * pTransceiversCount )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( ppTransceivers == NULL ) ||
        ( pTransceiversCount == NULL ) )
    {
        LogError( ( "Invalid input." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        *ppTransceivers = pCtx->transceivers;
        *pTransceiversCount = pCtx->transceiverCount;
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_GetLocalUserInfo( PeerConnectionContext_t * pCtx,
                                                        PeerConnectionUserInfo_t * pLocalUserInfo )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pLocalUserInfo == NULL ) )
    {
        LogError( ( "Invalid input." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pLocalUserInfo->pCname = pCtx->iceControllerContext.localCname;
        pLocalUserInfo->cnameLength = strlen( pCtx->iceControllerContext.localCname );
        pLocalUserInfo->pUserName = pCtx->iceControllerContext.localUserName;
        pLocalUserInfo->userNameLength = strlen( pCtx->iceControllerContext.localUserName );
        pLocalUserInfo->pPassword = pCtx->iceControllerContext.localPassword;
        pLocalUserInfo->passwordLength = strlen( pCtx->iceControllerContext.localPassword );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_CreateSession( PeerConnectionContext_t * pCtx,
                                                     const char * pRemoteClientId,
                                                     size_t remoteClientIdLength,
                                                     const char ** ppLocalFingerprint,
                                                     size_t * pLocalFingerprint )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( ( pCtx == NULL ) ||
        ( pRemoteClientId == NULL ) )
    {
        LogError( ( "Invalid input." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_CreateDtlsSession( &pCtx->iceControllerContext, pRemoteClientId, remoteClientIdLength, ppLocalFingerprint, pLocalFingerprint );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "IceController_CreateDtlsSession fail, result: %d.", iceControllerResult ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_CREATE_DTLS_SESSION;
        }
    }

    return ret;
}
