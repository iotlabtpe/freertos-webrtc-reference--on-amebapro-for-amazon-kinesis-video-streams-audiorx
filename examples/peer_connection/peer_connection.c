#include <stdlib.h>
#include "FreeRTOS.h"
#include "task.h"
#include "logging.h"
#include "peer_connection.h"
#include "peer_connection_srtp.h"
#include "signaling_controller.h"
#include "rtp_api.h"
#include "rtcp_api.h"

#include "lwip/sockets.h"

#define PEER_CONNECTION_SESSION_TASK_NAME "PcSessionTsk"
#define PEER_CONNECTION_SESSION_RX_TASK_NAME "PcRxTsk" // For Ice controller to monitor socket Rx path
#define PEER_CONNECTION_MESSAGE_QUEUE_NAME "/PcSessionMq"

#define PEER_CONNECTION_MAX_QUEUE_MSG_NUM ( 30 )
#define PEER_CONNECTION_JSON_CANDIDATE_MAX_LENGTH ( 512 )

#define PEER_CONNECTION_ICE_CANDIDATE_JSON_TEMPLATE "{\"candidate\":\"%.*s\",\"sdpMid\":\"0\",\"sdpMLineIndex\":0}"
#define PEER_CONNECTION_ICE_CANDIDATE_JSON_MAX_LENGTH ( 1024 )
#define PEER_CONNECTION_ICE_CANDIDATE_JSON_IPV4_TEMPLATE "candidate:%u 1 udp %lu %d.%d.%d.%d %d typ %s raddr 0.0.0.0 rport 0 generation 0 network-cost 999"
#define PEER_CONNECTION_ICE_CANDIDATE_JSON_IPV6_TEMPLATE "candidate:%u 1 udp %lu %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X "\
    "%d typ %s raddr ::/0 rport 0 generation 0 network-cost 999"

#define PEER_CONNECTION_CANDIDATE_TYPE_HOST_STRING "host"
#define PEER_CONNECTION_CANDIDATE_TYPE_SRFLX_STRING "srflx"
#define PEER_CONNECTION_CANDIDATE_TYPE_PRFLX_STRING "prflx"
#define PEER_CONNECTION_CANDIDATE_TYPE_RELAY_STRING "relay"
#define PEER_CONNECTION_CANDIDATE_TYPE_UNKNOWN_STRING "unknown"

extern void IceControllerSocketListener_Task( void * pParameter );
static void PeerConnection_SessionTask( void * pParameter );
static void SessionProcessEndlessLoop( PeerConnectionSession_t * pSession );
static void HandleRequest( PeerConnectionSession_t * pSession,
                           MessageQueueHandler_t * pRequestQueue );
static PeerConnectionResult_t HandleAddRemoteCandidateRequest( PeerConnectionSession_t * pSession,
                                                               PeerConnectionSessionRequestMessage_t * pRequestMessage );
static PeerConnectionResult_t HandleConnectivityCheckRequest( PeerConnectionSession_t * pSession,
                                                              PeerConnectionSessionRequestMessage_t * pRequestMessage );
static int32_t ExecuteDtlsHandshake( PeerConnectionSession_t * pSession,
                                     int socketFd,
                                     IceCandidate_t * pRemoteCandidate );

static void PeerConnection_SessionTask( void * pParameter )
{
    PeerConnectionSession_t * pSession = ( PeerConnectionSession_t * ) pParameter;

    SessionProcessEndlessLoop( pSession );

    for( ;; )
    {
        LogError( ( "PeerConnectionTask returns unexpectly." ) );
        vTaskDelay( pdMS_TO_TICKS( 2000 ) );
    }
}

static void SessionProcessEndlessLoop( PeerConnectionSession_t * pSession )
{
    uint8_t skipProcess = 0;

    if( pSession == NULL )
    {
        LogError( ( "Invalid input, pSession: %p", pSession ) );
        skipProcess = 1;
    }

    for( ; !skipProcess; )
    {
        HandleRequest( pSession,
                       &pSession->requestQueue );
    }
}

static void HandleRequest( PeerConnectionSession_t * pSession,
                           MessageQueueHandler_t * pRequestQueue )
{
    MessageQueueResult_t retMessageQueue;
    PeerConnectionSessionRequestMessage_t requestMsg;
    size_t requestMsgLength;

    /* Handle event. */
    requestMsgLength = sizeof( PeerConnectionSessionRequestMessage_t );
    retMessageQueue = MessageQueue_Recv( pRequestQueue,
                                         &requestMsg,
                                         &requestMsgLength );
    if( retMessageQueue == MESSAGE_QUEUE_RESULT_OK )
    {
        /* Received message, process it. */
        LogDebug( ( "Receive request type: %d", requestMsg.requestType ) );
        switch( requestMsg.requestType )
        {
            case PEER_CONNECTION_SESSION_REQUEST_TYPE_ADD_REMOTE_CANDIDATE:
                ( void ) HandleAddRemoteCandidateRequest( pSession,
                                                          &requestMsg );
                break;
            case PEER_CONNECTION_SESSION_REQUEST_TYPE_CONNECTIVITY_CHECK:
                ( void ) HandleConnectivityCheckRequest( pSession,
                                                         &requestMsg );
                break;
            default:
                /* Unknown request, drop it. */
                LogDebug( ( "Dropping unknown request %d", requestMsg.requestType ) );
                break;
        }
    }
}

static PeerConnectionResult_t HandleAddRemoteCandidateRequest( PeerConnectionSession_t * pSession,
                                                               PeerConnectionSessionRequestMessage_t * pRequestMessage )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;
    IceControllerCandidate_t * pRemoteCandidate = ( IceControllerCandidate_t * )&pRequestMessage->peerConnectionSessionRequestContent;
    IceRemoteCandidateInfo_t remoteCandidateInfo;

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        remoteCandidateInfo.candidateType = pRemoteCandidate->candidateType;
        remoteCandidateInfo.pEndpoint = &( pRemoteCandidate->iceEndpoint );
        remoteCandidateInfo.priority = pRemoteCandidate->priority;
        remoteCandidateInfo.remoteProtocol = pRemoteCandidate->protocol;

        iceControllerResult = IceController_AddRemoteCandidate( &pSession->iceControllerContext, &remoteCandidateInfo );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to add remote candidate." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_ADD_REMOTE_CANDIDATE;
        }
    }

    return ret;
}

static PeerConnectionResult_t HandleConnectivityCheckRequest( PeerConnectionSession_t * pSession,
                                                              PeerConnectionSessionRequestMessage_t * pRequestMessage )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    ( void ) pRequestMessage;

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_SendConnectivityCheck( &pSession->iceControllerContext );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to add remote candidate." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_CONNECTIVITY_CHECK;
        }
    }

    return ret;
}

static PeerConnectionResult_t SendRemoteCandidateRequest( PeerConnectionSession_t * pSession,
                                                          IceControllerCandidate_t * pRemoteCandidate )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    MessageQueueResult_t retMessageQueue;
    IceControllerCandidate_t * pMessageContent;
    PeerConnectionSessionRequestMessage_t requestMessage = {
        .requestType = PEER_CONNECTION_SESSION_REQUEST_TYPE_ADD_REMOTE_CANDIDATE,
    };

    if( ( pSession == NULL ) || ( pRemoteCandidate == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pRemoteCandidate: %p", pSession, pRemoteCandidate ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pMessageContent = &requestMessage.peerConnectionSessionRequestContent.remoteCandidate;
        memcpy( pMessageContent,
                pRemoteCandidate,
                sizeof( IceControllerCandidate_t ) );

        retMessageQueue = MessageQueue_Send( &pSession->requestQueue,
                                             &requestMessage,
                                             sizeof( PeerConnectionSessionRequestMessage_t ) );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to send message queue, error: %d", retMessageQueue ) );
            ret = PEER_CONNECTION_RESULT_FAIL_MQ_SEND;
        }
    }

    return ret;
}

static const char * GetCandidateTypeString( IceCandidateType_t candidateType )
{
    const char * ret;

    switch( candidateType )
    {
        case ICE_CANDIDATE_TYPE_HOST:
            ret = PEER_CONNECTION_CANDIDATE_TYPE_HOST_STRING;
            break;
        case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            ret = PEER_CONNECTION_CANDIDATE_TYPE_PRFLX_STRING;
            break;
        case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            ret = PEER_CONNECTION_CANDIDATE_TYPE_SRFLX_STRING;
            break;
        case ICE_CANDIDATE_TYPE_RELAYED:
            ret = PEER_CONNECTION_CANDIDATE_TYPE_RELAY_STRING;
            break;
        default:
            ret = PEER_CONNECTION_CANDIDATE_TYPE_UNKNOWN_STRING;
            break;
    }

    return ret;
}

static int32_t SendIceCandidateCompleteCallback( SignalingControllerEventStatus_t status,
                                                 void * pUserContext )
{
    LogDebug( ( "Freeing buffer at %p", pUserContext ) );
    free( pUserContext );

    return 0;
}

static int32_t OnIceEventLocalCandidateReady( PeerConnectionSession_t * pSession,
                                              const IceCandidate_t * pLocalCandidate,
                                              size_t localCandidateIndex )
{
    int32_t ret = 0;
    int written;
    char * pBuffer;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerEventMessage_t eventMessage = {
        .event = SIGNALING_CONTROLLER_EVENT_SEND_WSS_MESSAGE,
        .onCompleteCallback = SendIceCandidateCompleteCallback,
        .pOnCompleteCallbackContext = NULL,
    };
    char candidateStringBuffer[ PEER_CONNECTION_JSON_CANDIDATE_MAX_LENGTH ];

    if( ( pSession == NULL ) || ( pLocalCandidate == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pLocalCandidate: %p",
                    pSession, pLocalCandidate ) );
        ret = -10;
    }

    if( ret == 0 )
    {
        if( pLocalCandidate->endpoint.transportAddress.family == STUN_ADDRESS_IPv4 )
        {
            written = snprintf( candidateStringBuffer, PEER_CONNECTION_JSON_CANDIDATE_MAX_LENGTH, PEER_CONNECTION_ICE_CANDIDATE_JSON_IPV4_TEMPLATE,
                                localCandidateIndex,
                                pLocalCandidate->priority,
                                pLocalCandidate->endpoint.transportAddress.address[0], pLocalCandidate->endpoint.transportAddress.address[1], pLocalCandidate->endpoint.transportAddress.address[2], pLocalCandidate->endpoint.transportAddress.address[3],
                                pLocalCandidate->endpoint.transportAddress.port,
                                GetCandidateTypeString( pLocalCandidate->candidateType ) );
        }
        else
        {
            written = snprintf( candidateStringBuffer, PEER_CONNECTION_JSON_CANDIDATE_MAX_LENGTH, PEER_CONNECTION_ICE_CANDIDATE_JSON_IPV6_TEMPLATE,
                                localCandidateIndex,
                                pLocalCandidate->priority,
                                pLocalCandidate->endpoint.transportAddress.address[0], pLocalCandidate->endpoint.transportAddress.address[1], pLocalCandidate->endpoint.transportAddress.address[2], pLocalCandidate->endpoint.transportAddress.address[3],
                                pLocalCandidate->endpoint.transportAddress.address[4], pLocalCandidate->endpoint.transportAddress.address[5], pLocalCandidate->endpoint.transportAddress.address[6], pLocalCandidate->endpoint.transportAddress.address[7],
                                pLocalCandidate->endpoint.transportAddress.address[8], pLocalCandidate->endpoint.transportAddress.address[9], pLocalCandidate->endpoint.transportAddress.address[10], pLocalCandidate->endpoint.transportAddress.address[11],
                                pLocalCandidate->endpoint.transportAddress.address[12], pLocalCandidate->endpoint.transportAddress.address[13], pLocalCandidate->endpoint.transportAddress.address[14], pLocalCandidate->endpoint.transportAddress.address[15],
                                pLocalCandidate->endpoint.transportAddress.port,
                                GetCandidateTypeString( pLocalCandidate->candidateType ) );
        }

        if( written < 0 )
        {
            LogError( ( "snprintf returns fail, error: %d", written ) );
            ret = -11;
        }
    }

    if( ret == 0 )
    {
        /* Format this into candidate string. */
        pBuffer = ( char * ) malloc( PEER_CONNECTION_ICE_CANDIDATE_JSON_MAX_LENGTH );
        LogDebug( ( "Allocating buffer at %p", pBuffer ) );
        memset( pBuffer, 0, PEER_CONNECTION_ICE_CANDIDATE_JSON_MAX_LENGTH );

        written = snprintf( pBuffer, PEER_CONNECTION_ICE_CANDIDATE_JSON_MAX_LENGTH, PEER_CONNECTION_ICE_CANDIDATE_JSON_TEMPLATE,
                            written, candidateStringBuffer );

        if( written < 0 )
        {
            LogError( ( "snprintf returns fail, error: %d", written ) );
            ret = -12;
            free( pBuffer );
        }
    }

    if( ret == 0 )
    {
        eventMessage.eventContent.correlationIdLength = 0U;
        eventMessage.eventContent.messageType = SIGNALING_TYPE_MESSAGE_ICE_CANDIDATE;
        eventMessage.eventContent.pDecodeMessage = pBuffer;
        eventMessage.eventContent.decodeMessageLength = written;
        memcpy( eventMessage.eventContent.remoteClientId, pSession->remoteClientId, pSession->remoteClientIdLength );
        eventMessage.eventContent.remoteClientIdLength = pSession->remoteClientIdLength;

        /* We dynamically allocate buffer for signaling controller to keep using it.
         * callback it as context to free memory. */
        eventMessage.pOnCompleteCallbackContext = pBuffer;

        signalingControllerReturn = SignalingController_SendMessage( pSession->pSignalingControllerContext, &eventMessage );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Send signaling message fail, result: %d", signalingControllerReturn ) );
            ret = -13;
            free( pBuffer );
        }
        else
        {
            LogDebug( ( "Sent local candidate to remote peer, msg(%d): %.*s",
                        written,
                        written,
                        pBuffer ) );
        }
    }

    return ret;
}

static int32_t OnIceEventConnectivityCheck( PeerConnectionSession_t * pSession )
{
    int32_t ret = 0;
    MessageQueueResult_t retMessageQueue;
    PeerConnectionSessionRequestMessage_t requestMessage = {
        .requestType = PEER_CONNECTION_SESSION_REQUEST_TYPE_CONNECTIVITY_CHECK,
    };

    if( pSession == NULL )
    {
        LogError( ( "Invalid input, pSession: %p", pSession ) );
        ret = -10;
    }

    if( ret == 0 )
    {
        retMessageQueue = MessageQueue_Send( &pSession->requestQueue,
                                             &requestMessage,
                                             sizeof( PeerConnectionSessionRequestMessage_t ) );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            ret = -11;
        }
    }

    return ret;
}

static int32_t OnIceEventPeerToPeerConnectionFound( PeerConnectionSession_t * pSession,
                                                    int socketFd,
                                                    IceCandidate_t * pRemoteCandidate )
{
    int32_t ret = 0;
    PeerConnectionResult_t retPeerConnection;
    int i;

    if( ( pSession == NULL ) ||
        ( pRemoteCandidate == NULL ) ||
        ( socketFd < 0 ) )
    {
        LogError( ( "Invalid input, pSession: %p, pRemoteCandidate: %p, socketFd: %d", pSession, pRemoteCandidate, socketFd ) );
        ret = -10;
    }

    if( ret == 0 )
    {
        pSession->state = PEER_CONNECTION_SESSION_STATE_P2P_CONNECTION_FOUND;

        /* Execute DTLS handshaking. */
        ret = ExecuteDtlsHandshake( pSession, socketFd, pRemoteCandidate );
    }

    if( ret == 0 )
    {
        /* Initialize SRTP sessions. */
        retPeerConnection = PeerConnectionSrtp_Init( pSession );
        if( retPeerConnection != PEER_CONNECTION_RESULT_OK )
        {
            LogError( ( "Fail to create SRTP sessions, ret: %d", retPeerConnection ) );
            ret = -12;
        }
    }

    if( ret == 0 )
    {
        pSession->state = PEER_CONNECTION_SESSION_STATE_CONNECTION_READY;
        for( i = 0; i < pSession->pCtx->transceiverCount; i++ )
        {
            if( pSession->pCtx->pTransceivers[i]->onPcEventCallbackFunc )
            {
                pSession->pCtx->pTransceivers[i]->onPcEventCallbackFunc( pSession->pCtx->pTransceivers[i]->pOnPcEventCustomContext,
                                                                         TRANSCEIVER_CB_EVENT_REMOTE_PEER_READY,
                                                                         NULL );
            }
        }
    }

    return ret;
}

static int32_t HandleIceEventCallback( void * pCustomContext,
                                       IceControllerCallbackEvent_t event,
                                       IceControllerCallbackContent_t * pEventMsg )
{
    int32_t ret = 0;
    PeerConnectionSession_t * pSession = ( PeerConnectionSession_t * ) pCustomContext;
    IceControllerLocalCandidateReadyMsg_t * pLocalCandidateReadyMsg = NULL;
    IceControllerPeerToPeerConnectionFoundMsg_t * pPeerToPeerConnectionFoundMsg = NULL;

    if( ( pCustomContext == NULL ) )
    {
        LogError( ( "Invalid input, pCustomContext: %p, pEventMsg: %p",
                    pCustomContext, pEventMsg ) );
        ret = -1;
    }
    else if( ( event == ICE_CONTROLLER_CB_EVENT_NONE ) || ( event >= ICE_CONTROLLER_CB_EVENT_MAX ) )
    {
        LogError( ( "Unknown event: %d",
                    event ) );
        ret = -2;
    }
    else
    {
        switch( event )
        {
            case ICE_CONTROLLER_CB_EVENT_LOCAL_CANDIDATE_READY:
                if( pEventMsg != NULL )
                {
                    pLocalCandidateReadyMsg = &pEventMsg->iceControllerCallbackContent.localCandidateReadyMsg;
                    ret = OnIceEventLocalCandidateReady( pSession, pLocalCandidateReadyMsg->pLocalCandidate, pLocalCandidateReadyMsg->localCandidateIndex );
                }
                else
                {
                    LogError( ( "Event message pointer must be valid in event: %d.", event ) );
                }
                break;
            case ICE_CONTROLLER_CB_EVENT_CONNECTIVITY_CHECK_TIMEOUT:
                ret = OnIceEventConnectivityCheck( pSession );
                break;
            case ICE_CONTROLLER_CB_EVENT_PEER_TO_PEER_CONNECTION_FOUND:
                pPeerToPeerConnectionFoundMsg = &pEventMsg->iceControllerCallbackContent.peerTopeerConnectionFoundMsg;
                ret = OnIceEventPeerToPeerConnectionFound( pSession, pPeerToPeerConnectionFoundMsg->socketFd, pPeerToPeerConnectionFoundMsg->pRemoteCandidate );
                break;
            default:
                LogError( ( "Unknown event: %d", event ) );
                break;
        }
    }

    return ret;
}

static int32_t ExecuteDtlsHandshake( PeerConnectionSession_t * pSession,
                                     int socketFd,
                                     IceCandidate_t * pRemoteCandidate )
{
    int32_t ret = 0;
    DtlsTransportStatus_t xNetworkStatus = DTLS_TRANSPORT_SUCCESS;
    BaseType_t retUdpTransport;
    DtlsSession_t * pDtlsSession = NULL;
    char remoteIpAddr[ INET_ADDRSTRLEN ];
    const char * pRemoteIpPos;

    if( ( pSession == NULL ) || ( pRemoteCandidate == NULL ) || ( socketFd < 0 ) )
    {
        LogError( ( "Invalid input, pSession: %p, pRemoteCandidate: %p, socketFd: %d", pSession, pRemoteCandidate, socketFd ) );
        ret = -20;
    }

    if( ret == 0 )
    {
        /* Set the pParams member of the network context with desired transport. */
        pDtlsSession = &pSession->dtlsSession;
        pDtlsSession->xNetworkContext.pParams = &pDtlsSession->xDtlsTransportParams;
        retUdpTransport = UDP_Sockets_CreateAndAssign( &pDtlsSession->xNetworkContext.pParams->udpSocket, socketFd );
        if( retUdpTransport != UDP_SOCKETS_ERRNO_NONE )
        {
            LogError( ( "Fail to create UDP socket descriptor, ret: %ld", retUdpTransport ) );
            ret = -21;
        }
    }

    if( ret == 0 )
    {
        /* Set transport interface. */
        pDtlsSession->xTransportInterface.pNetworkContext = ( NetworkContext_t * ) &pDtlsSession->xNetworkContext;
        pDtlsSession->xTransportInterface.send = ( TransportSend_t ) DTLS_send;
        pDtlsSession->xTransportInterface.recv = ( TransportRecv_t ) DTLS_recv;

        // /* Set the network credentials. */
        /* Disable SNI server name indication*/
        // https://mbed-tls.readthedocs.io/en/latest/kb/how-to/use-sni/
        pDtlsSession->xNetworkCredentials.disableSni = pdTRUE;

        pRemoteIpPos = inet_ntop( AF_INET,
                                  pRemoteCandidate->endpoint.transportAddress.address,
                                  remoteIpAddr,
                                  INET_ADDRSTRLEN );
        LogInfo( ( "Start DTLS handshaking with %s:%d", pRemoteIpPos ? pRemoteIpPos : "UNKNOWN", pRemoteCandidate->endpoint.transportAddress.port ) );
        if( pRemoteIpPos == NULL )
        {
            LogError( ( "Unknown remote candidate." ) );
            ret = -22;
        }
    }

    if( ret == 0 )
    {
        if( NULL == pSession->pCtx->dtlsContext.localCert.raw.p )
        {
            LogError( ( "Fail to get answer cert: NULL == pSession->pCtx->dtlsContext.localCert.raw.p" ) );
            ret = -23;
        }
        else
        {
            /* Assign local cert to the DTLS session. */
            LogDebug( ( "setting pDtlsSession->xNetworkCredentials.pClientCert" ) );
            pDtlsSession->xNetworkCredentials.pClientCert = &pSession->pCtx->dtlsContext.localCert;

            // /* Assign local key to the DTLS session. */
            LogDebug( ( "setting pDtlsSession->xNetworkCredentials.pPrivateKey" ) );
            pDtlsSession->xNetworkCredentials.pPrivateKey = &pSession->pCtx->dtlsContext.localKey;

            /* Attempt to create a DTLS connection. */
            xNetworkStatus = DTLS_Connect( &pDtlsSession->xNetworkContext,
                                           &pDtlsSession->xNetworkCredentials,
                                           pRemoteIpPos,
                                           pRemoteCandidate->endpoint.transportAddress.port );

            if( xNetworkStatus != DTLS_TRANSPORT_SUCCESS )
            {
                LogError( ( "Fail to connect with server with return % d ", xNetworkStatus ) );
                ret = -24;
            }
        }
    }

    if( ret == 0 )
    {
        /* Verify remote fingerprint (if remote cert fingerprint is the expected one) */
        xNetworkStatus = dtlsSessionVerifyRemoteCertificateFingerprint( &pDtlsSession->xNetworkContext.pParams->dtlsSslContext,
                                                                        pSession->remoteCertFingerprint,
                                                                        pSession->remoteCertFingerprintLength );

        if( xNetworkStatus != DTLS_TRANSPORT_SUCCESS )
        {
            LogError( ( "Fail to dtlsSessionVerifyRemoteCertificateFingerprint with return %d ", xNetworkStatus ) );
            ret = -25;
        }
    }

    if( ret == 0 )
    {
        /* Retrieve key material into DTLS session. */
        xNetworkStatus = dtlsSessionPopulateKeyingMaterial( &pDtlsSession->xNetworkContext.pParams->dtlsSslContext,
                                                            &pDtlsSession->xNetworkCredentials.dtlsKeyingMaterial );

        if( xNetworkStatus != DTLS_TRANSPORT_SUCCESS )
        {
            LogError( ( "Fail to dtlsSessionPopulateKeyingMaterial with return %d ", xNetworkStatus ) );
            ret = -26;
        }
        else
        {
            LogDebug( ( "dtlsSessionPopulateKeyingMaterial with key_length: %i ", pDtlsSession->xNetworkCredentials.dtlsKeyingMaterial.key_length ) );
        }
    }

    return ret;
}

static int32_t HandleRtpRtcpPackets( void * pCustomContext,
                                     uint8_t * pBuffer,
                                     size_t bufferLength )
{
    int32_t ret = 0;
    PeerConnectionSession_t * pSession = ( PeerConnectionSession_t * ) pCustomContext;
    PeerConnectionResult_t resultPeerConnection;

    if( ( pCustomContext == NULL ) || ( pBuffer == NULL ) )
    {
        LogWarn( ( "Invalid input, pCustomContext: %p, pBuffer: %p",
                   pCustomContext, pBuffer ) );
        ret = -1;
    }

    if( ret == 0 )
    {
        if( ( bufferLength >= 2 ) && ( pBuffer[1] >= 192 ) && ( pBuffer[1] <= 223 ) )
        {
            /* RTCP packet */
            LogInfo( ( "Receiving RTCP packets with length %u", bufferLength ) );
            resultPeerConnection = PeerConnectionSrtp_HandleSrtcpPacket( pSession, pBuffer, bufferLength );
            if( resultPeerConnection != PEER_CONNECTION_RESULT_OK )
            {
                LogWarn( ( "Failed to handle SRTCP packets, result: %d", resultPeerConnection ) );
                ret = -2;
            }
        }
        else
        {
            /* RTP packet */
            LogInfo( ( "Receiving RTP packets with length %u", bufferLength ) );
            resultPeerConnection = PeerConnectionSrtp_HandleSrtpPacket( pSession, pBuffer, bufferLength );
            if( resultPeerConnection != PEER_CONNECTION_RESULT_OK )
            {
                LogWarn( ( "Failed to handle SRTP packets, result: %d", resultPeerConnection ) );
                ret = -2;
            }
        }
    }

    return ret;
}

/* Generate a printable string that does not
 * need to be escaped when encoding in JSON
 */
static void generateJSONValidString( char * pDst,
                                     size_t length )
{
    size_t i = 0;
    uint8_t skipProcess = 0;
    const char jsonCharSet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    const size_t jsonCharSetLength = strlen( jsonCharSet );

    if( pDst == NULL )
    {
        skipProcess = 1;
    }

    if( skipProcess == 0 )
    {
        for( i = 0; i < length; i++ )
        {
            pDst[i] = jsonCharSet[ rand() % jsonCharSetLength ];
        }
    }
}

static PeerConnectionResult_t InitializeIceController( PeerConnectionSession_t * pSession,
                                                       SignalingControllerContext_t * pSignalingControllerContext )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( ( pSession == NULL ) || ( pSignalingControllerContext == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pSignalingControllerContext: %p",
                    pSession, pSignalingControllerContext ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_Init( &pSession->iceControllerContext,
                                                  pSignalingControllerContext,
                                                  HandleIceEventCallback,
                                                  pSession,
                                                  HandleRtpRtcpPackets,
                                                  pSession );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to initialize Ice Controller." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_INIT;
        }
    }

    return ret;
}

static PeerConnectionResult_t DestroyIceController( PeerConnectionSession_t * pSession )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    IceControllerResult_t iceControllerResult;

    if( pSession == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        iceControllerResult = IceController_Destroy( &pSession->iceControllerContext );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to destroy Ice Controller." ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESTROY;
        }
    }

    return ret;
}

static PeerConnectionResult_t AllocateTransceiver( PeerConnectionContext_t * pCtx,
                                                   Transceiver_t * pTransceiver )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( pCtx == NULL )
    {
        LogError( ( "Invalid input, pCtx: %p", pCtx ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( pCtx->transceiverCount < PEER_CONNECTION_TRANSCEIVER_MAX_COUNT )
        {
            pCtx->pTransceivers[ pCtx->transceiverCount++ ] = pTransceiver;
            pTransceiver->ssrc = ( uint32_t ) rand();
        }
        else
        {
            LogWarn( ( "No space to add transceiver" ) );
            ret = PEER_CONNECTION_RESULT_NO_FREE_TRANSCEIVER;
        }
    }

    return ret;
}

static PeerConnectionSession_t * GetExistingSession( PeerConnectionContext_t * pCtx,
                                                     const char * pRemoteClientId,
                                                     size_t remoteClientIdLength )
{
    PeerConnectionSession_t * pRet = NULL;
    int i;

    for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
    {
        if( ( pCtx->peerConnectionSessions[i].remoteClientIdLength == remoteClientIdLength ) &&
            ( strncmp( pCtx->peerConnectionSessions[i].remoteClientId, pRemoteClientId, remoteClientIdLength ) == 0 ) )
        {
            /* Found existing session. */
            pRet = &pCtx->peerConnectionSessions[i];
            break;
        }
    }

    return pRet;
}

static PeerConnectionSession_t * GetOrCreateSession( PeerConnectionContext_t * pCtx,
                                                     const char * pRemoteClientId,
                                                     size_t remoteClientIdLength )
{
    PeerConnectionSession_t * pRet = NULL;
    int i;

    for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
    {
        if( ( pCtx->peerConnectionSessions[i].remoteClientIdLength == remoteClientIdLength ) &&
            ( strncmp( pCtx->peerConnectionSessions[i].remoteClientId, pRemoteClientId, remoteClientIdLength ) == 0 ) )
        {
            /* Found existing session. */
            pRet = &pCtx->peerConnectionSessions[i];
            break;
        }
        else if( ( pRet == NULL ) && ( pCtx->peerConnectionSessions[i].remoteClientIdLength == 0 ) )
        {
            /* Found free session, keep looping to find existing one. */
            pRet = &pCtx->peerConnectionSessions[i];
        }
        else
        {
            /* Do nothing. */
        }
    }

    if( pRet && ( pCtx->peerConnectionSessions[i].remoteClientIdLength == 0 ) )
    {
        pRet->remoteClientIdLength = remoteClientIdLength;
        memcpy( pRet->remoteClientId, pRemoteClientId, remoteClientIdLength );
    }

    return pRet;
}

static PeerConnectionResult_t InitializeDtlsContext( PeerConnectionDtlsContext_t * pDtlsContext )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    DtlsTransportStatus_t xNetworkStatus = DTLS_TRANSPORT_SUCCESS;

    if( pDtlsContext == NULL )
    {
        LogError( ( "Invalid input, pDtlsContext: %p", pDtlsContext ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Generate local cert in DER format. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        xNetworkStatus = createCertificateAndKey( GENERATED_CERTIFICATE_BITS,
                                                  pdFALSE,
                                                  &pDtlsContext->localCert,
                                                  &pDtlsContext->localKey );
        if( xNetworkStatus != DTLS_TRANSPORT_SUCCESS )
        {
            LogError( ( "Fail to createCertificateAndKey, return %d", xNetworkStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_CERT_AND_KEY;
        }
    }

    // Generate cert fingerprint
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        xNetworkStatus = dtlsCreateCertificateFingerprint( &pDtlsContext->localCert,
                                                           pDtlsContext->localCertFingerprint,
                                                           CERTIFICATE_FINGERPRINT_LENGTH );
        if( xNetworkStatus != DTLS_TRANSPORT_SUCCESS )
        {
            LogError( ( "Fail to dtlsCertificateFingerprint answer cert, return %d", xNetworkStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_CERT_FINGERPRINT;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pDtlsContext->isInitialized = 1;
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_Init( PeerConnectionContext_t * pCtx,
                                            SignalingControllerContext_t * pSignalingControllerContext )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    MessageQueueResult_t retMessageQueue;
    int i;
    char tempName[ 20 ];

    if( ( pCtx == NULL ) || ( pSignalingControllerContext == NULL ) )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( pCtx, 0, sizeof( PeerConnectionContext_t ) );

        for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
        {
            /* Initialize request queue. */
            ( void ) snprintf( tempName, sizeof( tempName ), "%s%02d", PEER_CONNECTION_MESSAGE_QUEUE_NAME, i );

            /* Delete message queue from previous round. */
            MessageQueue_Destroy( NULL,
                                  tempName );

            retMessageQueue = MessageQueue_Create( &pCtx->peerConnectionSessions[i].requestQueue,
                                                   tempName,
                                                   sizeof( PeerConnectionSessionRequestMessage_t ),
                                                   PEER_CONNECTION_MAX_QUEUE_MSG_NUM );
            if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
            {
                LogError( ( "Fail to open message queue" ) );
                ret = PEER_CONNECTION_RESULT_FAIL_MQ_INIT;
                break;
            }

            /* Initialize session task. */
            ( void ) snprintf( tempName, sizeof( tempName ), "%s%02d", PEER_CONNECTION_SESSION_TASK_NAME, i );

            if( xTaskCreate( PeerConnection_SessionTask,
                             tempName,
                             4096,
                             &pCtx->peerConnectionSessions[i],
                             tskIDLE_PRIORITY + 2,
                             pCtx->peerConnectionSessions[i].pTaskHandler ) != pdPASS )
            {
                LogError( ( "xTaskCreate(%s) failed", tempName ) );
                ret = PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_CONTROLLER;
                break;
            }

            /* Initialize other modules. */
            ret = InitializeIceController( &pCtx->peerConnectionSessions[i], pSignalingControllerContext );
            if( ret != PEER_CONNECTION_RESULT_OK )
            {
                break;
            }

            ( void ) snprintf( tempName, sizeof( tempName ), "%s%02d", PEER_CONNECTION_SESSION_RX_TASK_NAME, i );
            if( xTaskCreate( IceControllerSocketListener_Task,
                             tempName,
                             4096,
                             &pCtx->peerConnectionSessions[i].iceControllerContext,
                             tskIDLE_PRIORITY + 1,
                             NULL ) != pdPASS )
            {
                LogError( ( "xTaskCreate(%s) failed", tempName ) );
                ret = PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_SOCK_LISTENER;
            }

            pCtx->peerConnectionSessions[i].pSignalingControllerContext = pSignalingControllerContext;
            pCtx->peerConnectionSessions[i].pCtx = pCtx;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        generateJSONValidString( pCtx->localUserName,
                                 PEER_CONNECTION_USER_NAME_LENGTH );
        pCtx->localUserName[ PEER_CONNECTION_USER_NAME_LENGTH ] = '\0';
        generateJSONValidString( pCtx->localPassword,
                                 PEER_CONNECTION_PASSWORD_LENGTH );
        pCtx->localPassword[ PEER_CONNECTION_PASSWORD_LENGTH ] = '\0';
        generateJSONValidString( pCtx->localCname,
                                 PEER_CONNECTION_CNAME_LENGTH );
        pCtx->localCname[ PEER_CONNECTION_CNAME_LENGTH ] = '\0';
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_Destroy( PeerConnectionContext_t * pCtx )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    int i;

    if( pCtx == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
        {
            /* Deinitialize Ice Controller. */
            ret = DestroyIceController( &pCtx->peerConnectionSessions[i] );
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_SetRemoteDescription( PeerConnectionContext_t * pCtx,
                                                            const PeerConnectionRemoteInfo_t * pRemoteInfo )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    PeerConnectionSession_t * pSession = NULL;
    IceControllerResult_t iceControllerResult;
    RtpResult_t resultRtp;
    RtcpResult_t resultRtcp;

    if( ( pCtx == NULL ) || ( pRemoteInfo == NULL ) ||
        ( pRemoteInfo->pRemoteClientId == NULL ) ||
        ( pRemoteInfo->pRemotePassword == NULL ) ||
        ( pRemoteInfo->pRemoteUserName == NULL ) ||
        ( pRemoteInfo->pRemoteCertFingerprint == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pRemoteInfo: %p", pCtx, pRemoteInfo ) );
        if( pRemoteInfo != NULL )
        {
            LogError( ( "Invalid input, pRemoteClientId: %p, pRemotePassword: %p, pRemoteUserName: %p, pRemoteCertFingerprint: %p",
                        pRemoteInfo->pRemoteClientId, pRemoteInfo->pRemotePassword, pRemoteInfo->pRemoteUserName, pRemoteInfo->pRemoteCertFingerprint ) );
        }
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else if( ( pRemoteInfo->remoteUserNameLength > PEER_CONNECTION_USER_NAME_LENGTH ) ||
             ( pRemoteInfo->remotePasswordLength > PEER_CONNECTION_PASSWORD_LENGTH ) ||
             ( pRemoteInfo->remoteCertFingerprintLength > PEER_CONNECTION_CERTIFICATE_FINGERPRINT_LENGTH ) )
    {
        LogError( ( "Invalid input, remoteUserNameLength: %u, remotePasswordLength: %u, remoteCertFingerprintLength: %u",
                    pRemoteInfo->remoteUserNameLength, pRemoteInfo->remotePasswordLength, pRemoteInfo->remoteCertFingerprintLength ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else
    {
        /* Pass input check. */
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( pRemoteInfo->remoteUserNameLength + PEER_CONNECTION_USER_NAME_LENGTH > ( PEER_CONNECTION_USER_NAME_LENGTH << 1 ) )
        {
            LogWarn( ( "Remote user name is too long to store, length: %u", pRemoteInfo->remoteUserNameLength ) );
            ret = ICE_CONTROLLER_RESULT_INVALID_REMOTE_USERNAME;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pSession = GetOrCreateSession( pCtx, pRemoteInfo->pRemoteClientId, pRemoteInfo->remoteClientIdLength );
        if( pSession == NULL )
        {
            /* No session available for this candidate. */
            LogWarn( ( "No available session found for remote client(%d): %.*s",
                       pRemoteInfo->remoteClientIdLength,
                       ( int ) pRemoteInfo->remoteClientIdLength, pRemoteInfo->pRemoteClientId ) );
            ret = PEER_CONNECTION_RESULT_NO_AVAILABLE_SESSION;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memcpy( pSession->remoteUserName,
                pRemoteInfo->pRemoteUserName,
                pRemoteInfo->remoteUserNameLength );
        pSession->remoteUserName[ pRemoteInfo->remoteUserNameLength ] = '\0';
        memcpy( pSession->remotePassword,
                pRemoteInfo->pRemotePassword,
                pRemoteInfo->remotePasswordLength );
        pSession->remotePassword[ pRemoteInfo->remotePasswordLength ] = '\0';
        snprintf( pSession->combinedName,
                  ( PEER_CONNECTION_USER_NAME_LENGTH << 1 ) + 2,
                  "%.*s:%.*s",
                  pRemoteInfo->remoteUserNameLength,
                  pRemoteInfo->pRemoteUserName,
                  PEER_CONNECTION_USER_NAME_LENGTH,
                  pCtx->localUserName );
        memcpy( pSession->remoteCertFingerprint,
                pRemoteInfo->pRemoteCertFingerprint,
                pRemoteInfo->remoteCertFingerprintLength );
        pSession->remoteCertFingerprint[ pRemoteInfo->remoteCertFingerprintLength ] = '\0';
        pSession->remoteCertFingerprintLength = pRemoteInfo->remoteCertFingerprintLength;

        iceControllerResult = IceController_Start( &pSession->iceControllerContext,
                                                   pCtx->localUserName,
                                                   PEER_CONNECTION_USER_NAME_LENGTH,
                                                   pCtx->localPassword,
                                                   PEER_CONNECTION_PASSWORD_LENGTH,
                                                   pSession->remoteUserName,
                                                   pRemoteInfo->remoteUserNameLength,
                                                   pSession->remotePassword,
                                                   pRemoteInfo->remotePasswordLength,
                                                   pSession->combinedName,
                                                   strlen( pSession->combinedName ) );
        if( iceControllerResult != ICE_CONTROLLER_RESULT_OK )
        {
            LogWarn( ( "IceController_Start fail, result: %d.", iceControllerResult ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_START;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultRtp = Rtp_Init( &pCtx->rtpContext );
        if( resultRtp != RTP_RESULT_OK )
        {
            LogError( ( "Fail to initialize RTP context, result: %d", resultRtp ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTP_INIT;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultRtcp = Rtcp_Init( &pCtx->rtcpContext );
        if( resultRtcp != RTCP_RESULT_OK )
        {
            LogError( ( "Fail to initialize RTCP context, result: %d", resultRtcp ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTCP_INIT;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( pRemoteInfo->isVideoCodecPayloadSet )
        {
            pSession->rtpConfig.isVideoCodecPayloadSet = 1;
            pSession->rtpConfig.videoCodecPayload = pRemoteInfo->videoCodecPayload;
            pSession->rtpConfig.videoSequenceNumber = 0U;
        }

        if( pRemoteInfo->isAudioCodecPayloadSet )
        {
            pSession->rtpConfig.isAudioCodecPayloadSet = 1;
            pSession->rtpConfig.audioCodecPayload = pRemoteInfo->audioCodecPayload;
            pSession->rtpConfig.audioSequenceNumber = 0U;
        }

        pSession->rtpConfig.videoCodecRtxPayload = pRemoteInfo->videoCodecRtxPayload;
        pSession->rtpConfig.videoRtxSequenceNumber = 0U;
        pSession->rtpConfig.audioCodecRtxPayload = pRemoteInfo->audioCodecRtxPayload;
        pSession->rtpConfig.audioRtxSequenceNumber = 0U;
        pSession->rtpConfig.twccId = pRemoteInfo->twccId;

        pSession->state = PEER_CONNECTION_SESSION_STATE_START;
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
    PeerConnectionSession_t * pSession = NULL;

    if( ( pCtx == NULL ) ||
        ( pRemoteClientId == NULL ) ||
        ( pDecodeMessage == NULL ) )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pSession = GetOrCreateSession( pCtx, pRemoteClientId, remoteClientIdLength );
        if( pSession == NULL )
        {
            /* No session available for this candidate. */
            LogWarn( ( "No available session found for remote client(%d): %.*s", remoteClientIdLength, ( int ) remoteClientIdLength, pRemoteClientId ) );
            ret = PEER_CONNECTION_RESULT_NO_AVAILABLE_SESSION;
        }
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
        ret = SendRemoteCandidateRequest( pSession, &candidate );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_AddTransceiver( PeerConnectionContext_t * pCtx,
                                                      Transceiver_t * pTransceiver )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( pCtx == NULL )
    {
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        ret = AllocateTransceiver( pCtx, pTransceiver );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_MatchTransceiverBySsrc( PeerConnectionContext_t * pCtx,
                                                              uint32_t ssrc,
                                                              const Transceiver_t ** ppTransceiver )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    int i;

    if( ( pCtx == NULL ) || ( ppTransceiver == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, ppTransceiver: %p", pCtx, ppTransceiver ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        *ppTransceiver = NULL;
        for( i = 0; i < pCtx->transceiverCount; i++ )
        {
            if( ssrc == pCtx->pTransceivers[i]->ssrc )
            {
                *ppTransceiver = pCtx->pTransceivers[i];
                break;
            }
        }

        if( i == pCtx->transceiverCount )
        {
            LogWarn( ( "No transceiver for SSRC: %lu", ssrc ) );
            ret = PEER_CONNECTION_RESULT_UNKNOWN_SSRC;
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_GetTransceivers( PeerConnectionContext_t * pCtx,
                                                       const Transceiver_t * pTransceivers[],
                                                       size_t * pTransceiversCount )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    int i;

    if( ( pCtx == NULL ) ||
        ( pTransceivers == NULL ) ||
        ( pTransceiversCount == NULL ) ||
        ( *pTransceiversCount > PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pTransceivers: %p, pTransceiversCount: %p",
                    pCtx, pTransceivers, pTransceiversCount ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        for( i = 0; i < pCtx->transceiverCount; i++ )
        {
            pTransceivers[i] = pCtx->pTransceivers[i];
        }
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
        pLocalUserInfo->pCname = pCtx->localCname;
        pLocalUserInfo->cnameLength = strlen( pCtx->localCname );
        pLocalUserInfo->pUserName = pCtx->localUserName;
        pLocalUserInfo->userNameLength = strlen( pCtx->localUserName );
        pLocalUserInfo->pPassword = pCtx->localPassword;
        pLocalUserInfo->passwordLength = strlen( pCtx->localPassword );
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
    DtlsSession_t * pDtlsSession = NULL;
    PeerConnectionSession_t * pSession = NULL;

    if( ( pCtx == NULL ) ||
        ( pRemoteClientId == NULL ) )
    {
        LogError( ( "Invalid input." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Get session pointer for DTLS session. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pSession = GetOrCreateSession( pCtx, pRemoteClientId, remoteClientIdLength );
        if( pSession == NULL )
        {
            /* No session available for this candidate. */
            LogWarn( ( "No available session found for remote client(%d): %.*s", remoteClientIdLength, ( int ) remoteClientIdLength, pRemoteClientId ) );
            ret = PEER_CONNECTION_RESULT_NO_AVAILABLE_SESSION;
        }
    }

    /* Generate answer cert in DER format */
    if( ( ret == PEER_CONNECTION_RESULT_OK ) && ( pCtx->dtlsContext.isInitialized == 0 ) )
    {
        /* pCtx->dtlsContext.isInitialized would be set to 1 in InitializeDtlsContext(). */
        ret = InitializeDtlsContext( &pCtx->dtlsContext );
    }

    /* Initialize DTLS session. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pDtlsSession = &pSession->dtlsSession;
        memset( pDtlsSession,
                0,
                sizeof( DtlsSession_t ) );
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        *ppLocalFingerprint = pCtx->dtlsContext.localCertFingerprint;
        *pLocalFingerprint = strlen( *ppLocalFingerprint );
    }

    return ret;
}

PeerConnectionResult_t PeerConnection_CloseSession( PeerConnectionContext_t * pCtx,
                                                    const char * pRemoteClientId,
                                                    size_t remoteClientIdLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    PeerConnectionSession_t * pSession = NULL;

    if( ( pCtx == NULL ) ||
        ( pRemoteClientId == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pRemoteClientId: %p", pCtx, pRemoteClientId ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Get existing session pointer for DTLS session. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pSession = GetExistingSession( pCtx, pRemoteClientId, remoteClientIdLength );
        if( pSession == NULL )
        {
            /* No existing session found. */
            LogWarn( ( "No existing session found to close for remote client(%d): %.*s", remoteClientIdLength, ( int ) remoteClientIdLength, pRemoteClientId ) );
            ret = PEER_CONNECTION_RESULT_NO_AVAILABLE_SESSION;
        }
    }

    /* TODO: close corresponding resources. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {

    }

    return ret;
}

PeerConnectionResult_t PeerConnection_WriteFrame( PeerConnectionContext_t * pCtx,
                                                  Transceiver_t * pTransceiver,
                                                  const PeerConnectionFrame_t * pFrame )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    int i;

    if( ( pCtx == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pFrame == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pTransceiver: %p, pFrame: %p",
                    pCtx, pTransceiver, pFrame ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Encode the frame into multiple payload buffers (>=1). */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
        {
            if( pCtx->peerConnectionSessions[i].state < PEER_CONNECTION_SESSION_STATE_CONNECTION_READY )
            {
                continue;
            }

            if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ) )
            {
                ret = PeerConnectionSrtp_WriteH264Frame( &pCtx->peerConnectionSessions[i], pTransceiver, pFrame );
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT ) )
            {

            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT ) )
            {

            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT ) )
            {

            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT ) )
            {

            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT ) )
            {

            }
            else
            {
                /* TODO: Unknown, no matching codec. */
                LogError( ( "Codec is not supported, codec bit map: 0x%x", ( int ) pTransceiver->codecBitMap ) );
                ret = PEER_CONNECTION_RESULT_UNKNOWN_TX_CODEC;
            }
        }
    }

    return ret;
}
