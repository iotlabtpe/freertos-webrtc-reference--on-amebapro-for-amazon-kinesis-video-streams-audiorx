#include <errno.h>
#include <time.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip_netconf.h"
#include "logging.h"
#include "ice_controller.h"
#include "ice_controller_private.h"
#include "ice_api.h"
#include "signaling_controller.h"

#define RX_BUFFER_SIZE ( 4096 )
#define ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_UNKNOWN "UNKNOWN"
#define ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_REQUEST "BINDING_REQUEST"
#define ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_SUCCESS "BINDING_SUCCESS_RESPONSE"
#define ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_FAILURE "BINDING_FAILURE_RESPONSE"
#define ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_INDICATION "BINDING_INDICATION"

uint8_t receiveBuffer[ RX_BUFFER_SIZE ];

static void getLocalIPAdresses( IceEndpoint_t * pLocalIceEndpoints,
                                size_t * pLocalIceEndpointsNum )
{
    size_t localEndpointsSize = *pLocalIceEndpointsNum;
    uint8_t * pIpv4Address;

    if( localEndpointsSize >= 1 )
    {
        pIpv4Address = LwIP_GetIP( 0 );
        pLocalIceEndpoints[ 0 ].transportAddress.family = STUN_ADDRESS_IPv4;
        pLocalIceEndpoints[ 0 ].transportAddress.port = 0;
        memcpy( pLocalIceEndpoints[ 0 ].transportAddress.address, pIpv4Address, STUN_IPV4_ADDRESS_SIZE );
        pLocalIceEndpoints[ 0 ].isPointToPoint = 0;

        *pLocalIceEndpointsNum = 1;
    }
}

static IceControllerResult_t createSocketConnection( int * pSocketFd,
                                                     IceEndpoint_t * pIceEndpoint,
                                                     IceSocketProtocol_t protocol )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    struct sockaddr_in ipv4Address;
    // struct sockaddr_in6 ipv6Addr;
    struct sockaddr * sockAddress = NULL;
    socklen_t addressLength;
    uint32_t socketTimeoutMs = 1U;
    uint32_t sendBufferSize = 0;

    *pSocketFd = socket( pIceEndpoint->transportAddress.family == STUN_ADDRESS_IPv4 ? AF_INET : AF_INET6,
                         protocol == ICE_SOCKET_PROTOCOL_UDP ? SOCK_DGRAM : SOCK_STREAM,
                         0 );

    if( *pSocketFd == -1 )
    {
        LogError( ( "socket() failed to create socket with errno: %s", strerror( errno ) ) );
        ret = ICE_CONTROLLER_RESULT_FAIL_SOCKET_CREATE;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        if( pIceEndpoint->transportAddress.family == STUN_ADDRESS_IPv4 )
        {
            memset( &ipv4Address, 0, sizeof( ipv4Address ) );
            ipv4Address.sin_family = AF_INET;
            ipv4Address.sin_port = 0; // use next available port
            memcpy( &ipv4Address.sin_addr, pIceEndpoint->transportAddress.address, STUN_IPV4_ADDRESS_SIZE );
            sockAddress = ( struct sockaddr * ) &ipv4Address;
            addressLength = sizeof( struct sockaddr_in );
        }
        else
        {
            /* TODO: skip IPv6 for now. */
            // memset( &ipv6Addr, 0x00, sizeof(ipv6Addr) );
            // ipv6Addr.sin6_family = AF_INET6;
            // ipv6Addr.sin6_port = 0; // use next available port
            // memcpy(&ipv6Addr.sin6_addr, pIceEndpoint->transportAddress.address, STUN_IPV4_ADDRESS_SIZE);
            // sockAddress = (struct sockaddr*) &ipv6Addr;
            // addressLength = sizeof(struct sockaddr_in6);
            ret = ICE_CONTROLLER_RESULT_IPV6_NOT_SUPPORT;
            close( *pSocketFd );
            *pSocketFd = -1;
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        if( bind( *pSocketFd, sockAddress, addressLength ) < 0 )
        {
            LogError( ( "socket() failed to bind socket with errno: %s", strerror( errno ) ) );
            ret = ICE_CONTROLLER_RESULT_FAIL_SOCKET_BIND;
            close( *pSocketFd );
            *pSocketFd = -1;
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        setsockopt( *pSocketFd, SOL_SOCKET, SO_SNDBUF, &sendBufferSize, sizeof( sendBufferSize ) );
        setsockopt( *pSocketFd, SOL_SOCKET, SO_RCVTIMEO, &socketTimeoutMs, sizeof( socketTimeoutMs ) );
        setsockopt( *pSocketFd, SOL_SOCKET, SO_SNDTIMEO, &socketTimeoutMs, sizeof( socketTimeoutMs ) );
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        if( getsockname( *pSocketFd, sockAddress, &addressLength ) < 0 )
        {
            LogError( ( "getsockname() failed with errno: %s", strerror( errno ) ) );
            ret = ICE_CONTROLLER_RESULT_FAIL_SOCKET_GETSOCKNAME;
            close( *pSocketFd );
            *pSocketFd = -1;
        }
        else
        {
            pIceEndpoint->transportAddress.port = ( uint16_t ) pIceEndpoint->transportAddress.family == STUN_ADDRESS_IPv4 ? ntohs( ipv4Address.sin_port ) : 0U;
        }
    }

    return ret;
}

static const char * getCandidateTypeString( IceCandidateType_t candidateType )
{
    const char * ret;

    switch( candidateType )
    {
    case ICE_CANDIDATE_TYPE_HOST:
        ret = ICE_CONTROLLER_CANDIDATE_TYPE_HOST_STRING;
        break;
    case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
        ret = ICE_CONTROLLER_CANDIDATE_TYPE_PRFLX_STRING;
        break;
    case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
        ret = ICE_CONTROLLER_CANDIDATE_TYPE_SRFLX_STRING;
        break;
    case ICE_CANDIDATE_TYPE_RELAYED:
        ret = ICE_CONTROLLER_CANDIDATE_TYPE_RELAY_STRING;
        break;
    default:
        ret = ICE_CONTROLLER_CANDIDATE_TYPE_UNKNOWN_STRING;
        break;
    }

    return ret;
}

static int32_t sendIceCandidateCompleteCallback( SignalingControllerEventStatus_t status,
                                                 void * pUserContext )
{
    LogDebug( ( "Freeing buffer at %p", pUserContext ) );
    free( pUserContext );

    return 0;
}

static IceControllerResult_t sendIceCandidate( IceControllerContext_t * pCtx,
                                               IceCandidate_t * pCandidate,
                                               IceControllerRemoteInfo_t * pRemoteInfo )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    int written;
    char * pBuffer;
    SignalingControllerResult_t signalingControllerReturn;
    SignalingControllerEventMessage_t eventMessage = {
        .event = SIGNALING_CONTROLLER_EVENT_SEND_WSS_MESSAGE,
        .onCompleteCallback = sendIceCandidateCompleteCallback,
        .pOnCompleteCallbackContext = NULL,
    };
    char pCandidateStringBuffer[ ICE_CANDIDATE_JSON_CANDIDATE_MAX_LENGTH ];

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        if( pCandidate->endpoint.transportAddress.family == STUN_ADDRESS_IPv4 )
        {
            written = snprintf( pCandidateStringBuffer, ICE_CANDIDATE_JSON_CANDIDATE_MAX_LENGTH, ICE_CANDIDATE_JSON_CANDIDATE_IPV4_TEMPLATE,
                                pCtx->candidateFoundationCounter++,
                                pCandidate->priority,
                                pCandidate->endpoint.transportAddress.address[0], pCandidate->endpoint.transportAddress.address[1], pCandidate->endpoint.transportAddress.address[2], pCandidate->endpoint.transportAddress.address[3],
                                pCandidate->endpoint.transportAddress.port,
                                getCandidateTypeString( pCandidate->candidateType ) );
        }
        else
        {
            written = snprintf( pCandidateStringBuffer, ICE_CANDIDATE_JSON_CANDIDATE_MAX_LENGTH, ICE_CANDIDATE_JSON_CANDIDATE_IPV6_TEMPLATE,
                                pCtx->candidateFoundationCounter++,
                                pCandidate->priority,
                                pCandidate->endpoint.transportAddress.address[0], pCandidate->endpoint.transportAddress.address[1], pCandidate->endpoint.transportAddress.address[2], pCandidate->endpoint.transportAddress.address[3],
                                pCandidate->endpoint.transportAddress.address[4], pCandidate->endpoint.transportAddress.address[5], pCandidate->endpoint.transportAddress.address[6], pCandidate->endpoint.transportAddress.address[7],
                                pCandidate->endpoint.transportAddress.address[8], pCandidate->endpoint.transportAddress.address[9], pCandidate->endpoint.transportAddress.address[10], pCandidate->endpoint.transportAddress.address[11],
                                pCandidate->endpoint.transportAddress.address[12], pCandidate->endpoint.transportAddress.address[13], pCandidate->endpoint.transportAddress.address[14], pCandidate->endpoint.transportAddress.address[15],
                                pCandidate->endpoint.transportAddress.port,
                                getCandidateTypeString( pCandidate->candidateType ) );
        }

        if( written < 0 )
        {
            LogError( ( "snprintf returns fail, errno: %s", strerror( errno ) ) );
            ret = ICE_CONTROLLER_RESULT_CANDIDATE_STRING_BUFFER_TOO_SMALL;
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        /* Format this into candidate string. */
        pBuffer = ( char * ) malloc( ICE_CANDIDATE_JSON_MAX_LENGTH );
        LogDebug( ( "Allocating buffer at %p", pBuffer ) );
        memset( pBuffer, 0, ICE_CANDIDATE_JSON_MAX_LENGTH );

        written = snprintf( pBuffer, ICE_CANDIDATE_JSON_MAX_LENGTH, ICE_CANDIDATE_JSON_TEMPLATE,
                            written, pCandidateStringBuffer );

        if( written < 0 )
        {
            LogError( ( "snprintf returns fail, errno: %s", strerror( errno ) ) );
            ret = ICE_CONTROLLER_RESULT_CANDIDATE_BUFFER_TOO_SMALL;
            free( pBuffer );
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        eventMessage.eventContent.correlationIdLength = 0U;
        eventMessage.eventContent.messageType = SIGNALING_TYPE_MESSAGE_ICE_CANDIDATE;
        eventMessage.eventContent.pDecodeMessage = pBuffer;
        eventMessage.eventContent.decodeMessageLength = written;
        memcpy( eventMessage.eventContent.remoteClientId, pRemoteInfo->remoteClientId, pRemoteInfo->remoteClientIdLength );
        eventMessage.eventContent.remoteClientIdLength = pRemoteInfo->remoteClientIdLength;

        /* We dynamically allocate buffer for signaling controller to keep using it.
         * callback it as context to free memory. */
        eventMessage.pOnCompleteCallbackContext = pBuffer;

        signalingControllerReturn = SignalingController_SendMessage( pCtx->pSignalingControllerContext, &eventMessage );
        if( signalingControllerReturn != SIGNALING_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Send signaling message fail, result: %d", signalingControllerReturn ) );
            ret = ICE_CONTROLLER_RESULT_CANDIDATE_SEND_FAIL;
            free( pBuffer );
        }
    }

    return ret;
}

IceControllerResult_t IceControllerNet_AttachPolling( IceControllerContext_t * pCtx,
                                                      IceControllerSocketContext_t * pSocketContext )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;

    if( ( pCtx == NULL ) || ( pSocketContext == NULL ) )
    {
        LogError( ( "Invalid input" ) );
        ret = ICE_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        ret = IceControllerSocketListener_AppendSocketHandler( pCtx, pSocketContext->socketFd, pSocketContext );
    }

    return ret;
}

void IceControllerNet_DetachPolling( IceControllerContext_t * pCtx,
                                     IceControllerSocketContext_t * pSocketContext )
{
    ( void ) IceControllerSocketListener_RemoveSocketHandler( pCtx, pSocketContext->socketFd, pSocketContext );
}

void IceControllerNet_FreeSocketContext( IceControllerContext_t * pCtx,
                                         IceControllerSocketContext_t * pSocketContext )
{
    if( pSocketContext->socketFd != -1 )
    {
        IceControllerNet_DetachPolling( pCtx, pSocketContext );

        close( pSocketContext->socketFd );
    }
}

extern uint16_t ReadUint16Swap( const uint8_t * pSrc );
extern uint16_t ReadUint16NoSwap( const uint8_t * pSrc );
static const char * convertStunMsgTypeToString( uint16_t stunMsgType )
{
    const char * ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_UNKNOWN;
    static ReadUint16_t readUint16Fn;
    static uint8_t isFirst = 1;
    uint8_t isLittleEndian;
    uint16_t msgType;

    if( isFirst )
    {
        isFirst = 0;
        isLittleEndian = ( *( uint8_t * )( &( uint16_t ) { 1 } ) == 1 );

        if( isLittleEndian != 0 )
        {
            readUint16Fn = ReadUint16Swap;
        }
        else
        {
            readUint16Fn = ReadUint16NoSwap;
        }
    }

    msgType = readUint16Fn( ( uint8_t * ) &stunMsgType );
    switch( msgType )
    {
    case STUN_MESSAGE_TYPE_BINDING_REQUEST:
        ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_REQUEST;
        break;
    case STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE:
        ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_SUCCESS;
        break;
    case STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE:
        ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_FAILURE;
        break;
    case STUN_MESSAGE_TYPE_BINDING_INDICATION:
        ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_BINDING_INDICATION;
        break;
    }

    return ret;
}

static void IceControllerNet_AddSrflxCandidate( IceControllerContext_t * pCtx,
                                                IceControllerRemoteInfo_t * pRemoteInfo,
                                                IceEndpoint_t * pLocalIceEndpoint )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    IceResult_t iceResult;
    uint32_t i;
    IceControllerSocketContext_t * pSocketContext;
    uint8_t stunBuffer[ ICE_CONTROLLER_STUN_MESSAGE_BUFFER_SIZE ];
    size_t stunBufferLength = ICE_CONTROLLER_STUN_MESSAGE_BUFFER_SIZE;
    char ipBuffer[ INET_ADDRSTRLEN ];

    for( i = 0; i < pCtx->iceServersCount; i++ )
    {
        /* Reset ret for every round. */
        ret = ICE_CONTROLLER_RESULT_OK;

        if( pCtx->iceServers[ i ].serverType != ICE_CONTROLLER_ICE_SERVER_TYPE_STUN )
        {
            /* Not STUN server, no need to create srflx candidate for this server. */
            continue;
        }
        else if( pCtx->iceServers[ i ].iceEndpoint.transportAddress.family != STUN_ADDRESS_IPv4 )
        {
            /* For srflx candidate, we only support IPv4 for now. */
            continue;
        }
        else
        {
            /* Do nothing, coverity happy. */
        }

        /* Only support IPv4 STUN for now. */
        if( pCtx->iceServers[ i ].iceEndpoint.transportAddress.family == STUN_ADDRESS_IPv4 )
        {
            pSocketContext = &pRemoteInfo->socketsContexts[ pRemoteInfo->socketsContextsCount ];
            ret = createSocketConnection( &pSocketContext->socketFd, pLocalIceEndpoint, ICE_SOCKET_PROTOCOL_UDP );
            LogDebug( ( "Create srflx candidate with fd %d, IP/port: %s/%d",
                        pSocketContext->socketFd,
                        IceControllerNet_LogIpAddressInfo( pLocalIceEndpoint, ipBuffer, sizeof( ipBuffer ) ),
                        pLocalIceEndpoint->transportAddress.port ) );
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            iceResult = Ice_AddServerReflexiveCandidate( &pRemoteInfo->iceContext,
                                                         pLocalIceEndpoint,
                                                         stunBuffer, &stunBufferLength );
            if( iceResult != ICE_RESULT_OK )
            {
                /* Free resource that already created. */
                LogError( ( "Ice_AddServerReflexiveCandidate fail, result: %d", iceResult ) );
                IceControllerNet_FreeSocketContext( pCtx, pSocketContext );
                ret = ICE_CONTROLLER_RESULT_FAIL_ADD_HOST_CANDIDATE;
                break;
            }
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            ret = IceControllerNet_SendPacket( pSocketContext, &pCtx->iceServers[ i ].iceEndpoint, stunBuffer, stunBufferLength );
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            ret = IceControllerNet_AttachPolling( pCtx, pSocketContext );
            if( ret != ICE_CONTROLLER_RESULT_OK )
            {
                /* Free resource that already created. */
                IceControllerNet_FreeSocketContext( pCtx, pSocketContext );
                break;
            }
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            pSocketContext->pLocalCandidate = &pRemoteInfo->iceContext.pLocalCandidates[ pRemoteInfo->iceContext.numLocalCandidates - 1 ];
            pSocketContext->candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
            pSocketContext->pRemoteInfo = pRemoteInfo;
            pRemoteInfo->socketsContextsCount++;
            pCtx->metrics.pendingSrflxCandidateNum++;
        }
    }
}

IceControllerResult_t IceControllerNet_ConvertIpString( const char * pIpAddr,
                                                        size_t ipAddrLength,
                                                        IceEndpoint_t * pDestinationIceEndpoint )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    char ipAddress[ ICE_CONTROLLER_IP_ADDR_STRING_BUFFER_LENGTH + 1 ];

    if( ipAddrLength > ICE_CONTROLLER_IP_ADDR_STRING_BUFFER_LENGTH )
    {
        LogWarn( ( "invalid IP address detected, IP: %.*s",
                   ( int ) ipAddrLength, pIpAddr ) );
        ret = ICE_CONTROLLER_RESULT_IP_BUFFER_TOO_SMALL;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        memcpy( ipAddress, pIpAddr, ipAddrLength );
        ipAddress[ ipAddrLength ] = '\0';

        if( inet_pton( AF_INET, ipAddress, pDestinationIceEndpoint->transportAddress.address ) == 1 )
        {
            pDestinationIceEndpoint->transportAddress.family = STUN_ADDRESS_IPv4;
        }
        else if( inet_pton( AF_INET6, ipAddress, pDestinationIceEndpoint->transportAddress.address ) == 1 )
        {
            pDestinationIceEndpoint->transportAddress.family = STUN_ADDRESS_IPv6;
        }
        else
        {
            ret = ICE_CONTROLLER_RESULT_INVALID_IP_ADDR;
        }
    }

    return ret;
}

IceControllerResult_t IceControllerNet_Htons( uint16_t port,
                                              uint16_t * pOutPort )
{
    *pOutPort = htons( port );

    return ICE_CONTROLLER_RESULT_OK;
}

IceControllerResult_t IceControllerNet_InitRemoteInfo( IceControllerRemoteInfo_t * pRemoteInfo )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    uint32_t i;

    for( i = 0; i < ICE_CONTROLLER_MAX_CANDIDATE_PAIR_COUNT; i++ )
    {
        /* Initialize all socket fd to -1. */
        pRemoteInfo->socketsContexts[i].socketFd = -1;
    }

    return ret;
}

IceControllerResult_t IceControllerNet_SendPacket( IceControllerSocketContext_t * pSocketContext,
                                                   IceEndpoint_t * pDestinationIceEndpoint,
                                                   uint8_t * pBuffer,
                                                   size_t length )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    int sentBytes, sendTotalBytes = 0;
    struct sockaddr * pDestinationAddress = NULL;
    struct sockaddr_in ipv4Address;
    struct sockaddr_in6 ipv6Address;
    socklen_t addressLength = 0;

    /* Set socket destination address, including IP type (v4/v6), IP address and port. */
    if( pDestinationIceEndpoint->transportAddress.family == STUN_ADDRESS_IPv4 )
    {
        memset( &ipv4Address, 0, sizeof( ipv4Address ) );
        ipv4Address.sin_family = AF_INET;
        ipv4Address.sin_port = htons( pDestinationIceEndpoint->transportAddress.port );
        memcpy( &ipv4Address.sin_addr, pDestinationIceEndpoint->transportAddress.address, STUN_IPV4_ADDRESS_SIZE );

        pDestinationAddress = ( struct sockaddr * ) &ipv4Address;
        addressLength = sizeof( ipv4Address );
    }
    else
    {
        memset( &ipv6Address, 0, sizeof( ipv6Address ) );
        ipv6Address.sin6_family = AF_INET6;
        ipv6Address.sin6_port = htons( pDestinationIceEndpoint->transportAddress.port );
        memcpy( &ipv6Address.sin6_addr, pDestinationIceEndpoint->transportAddress.address, STUN_IPV6_ADDRESS_SIZE );

        pDestinationAddress = ( struct sockaddr * ) &ipv6Address;
        addressLength = sizeof( ipv6Address );
    }

    /* Send data */
    while( sendTotalBytes < length )
    {
        sentBytes = sendto( pSocketContext->socketFd,
                            pBuffer + sendTotalBytes,
                            length - sendTotalBytes,
                            0,
                            pDestinationAddress,
                            addressLength );
        if( sentBytes < 0 )
        {
            if( ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) )
            {
                /* Just retry for these kinds of errno. */
            }
            else
            {
                LogWarn( ( "Send error, errno: %s", strerror( errno ) ) );
                ret = ICE_CONTROLLER_RESULT_FAIL_SOCKET_SENDTO;
                break;
            }
        }
        else
        {
            sendTotalBytes += sentBytes;
        }
    }

    return ret;
}

IceControllerResult_t IceControllerNet_AddLocalCandidates( IceControllerContext_t * pCtx,
                                                           IceControllerRemoteInfo_t * pRemoteInfo )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    IceResult_t iceResult;
    uint32_t i;
    IceCandidate_t * pCandidate;
    IceControllerSocketContext_t * pSocketContext;
    char ipBuffer[ INET_ADDRSTRLEN ];

    pCtx->localIceEndpointsCount = ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT;
    getLocalIPAdresses( pCtx->localEndpoints, &pCtx->localIceEndpointsCount );

    for( i = 0; i < pCtx->localIceEndpointsCount; i++ )
    {
        pSocketContext = &pRemoteInfo->socketsContexts[ pRemoteInfo->socketsContextsCount ];
        ret = createSocketConnection( &pSocketContext->socketFd, &pCtx->localEndpoints[i], ICE_SOCKET_PROTOCOL_UDP );

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            iceResult = Ice_AddHostCandidate( &pRemoteInfo->iceContext, &pCtx->localEndpoints[i] );
            if( iceResult != ICE_RESULT_OK )
            {
                /* Free resource that already created. */
                LogError( ( "Ice_AddHostCandidate fail, result: %d", iceResult ) );
                IceControllerNet_FreeSocketContext( pCtx, pSocketContext );
                ret = ICE_CONTROLLER_RESULT_FAIL_ADD_HOST_CANDIDATE;
                break;
            }
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            ret = IceControllerNet_AttachPolling( pCtx, pSocketContext );
            if( ret != ICE_CONTROLLER_RESULT_OK )
            {
                /* Free resource that already created. */
                IceControllerNet_FreeSocketContext( pCtx, pSocketContext );
                break;
            }
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            pCandidate = &( pRemoteInfo->iceContext.pLocalCandidates[ pRemoteInfo->iceContext.numLocalCandidates - 1 ] );
            ret = sendIceCandidate( pCtx, pCandidate, pRemoteInfo );
            if( ret != ICE_CONTROLLER_RESULT_OK )
            {
                /* Free resource that already created. */
                IceControllerNet_FreeSocketContext( pCtx, pSocketContext );
                break;
            }
        }

        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            pSocketContext->pLocalCandidate = pCandidate;
            pSocketContext->candidateType = ICE_CANDIDATE_TYPE_HOST;
            pSocketContext->pRemoteInfo = pRemoteInfo;
            pRemoteInfo->socketsContextsCount++;

            LogDebug( ( "Created host candidate with fd %d, IP/port: %s/%d",
                        pSocketContext->socketFd,
                        IceControllerNet_LogIpAddressInfo( &pCtx->localEndpoints[i], ipBuffer, sizeof( ipBuffer ) ),
                        pCtx->localEndpoints[i].transportAddress.port ) );
        }

        /* Prepare srflx candidates based on current host candidate. */
        if( ret == ICE_CONTROLLER_RESULT_OK )
        {
            IceControllerNet_AddSrflxCandidate( pCtx, pRemoteInfo, &pCtx->localEndpoints[i] );
        }
    }

    return ret;
}

IceControllerResult_t IceControllerNet_DetectRxPacket( IceControllerContext_t * pCtx,
                                                       IceControllerSocketContext_t * pSocketContext )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    MessageQueueResult_t retMessageQueue;
    IceControllerRequestMessage_t requestMessage = {
        .requestType = ICE_CONTROLLER_REQUEST_TYPE_DETECT_RX_PACKET,
    };

    if( ( pCtx == NULL ) || ( pSocketContext == NULL ) )
    {
        ret = ICE_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        requestMessage.requestContent.detectRxPacket.pSocketContext = pSocketContext;

        retMessageQueue = MessageQueue_Send( &pCtx->requestQueue, &requestMessage, sizeof( IceControllerRequestMessage_t ) );
        if( retMessageQueue != MESSAGE_QUEUE_RESULT_OK )
        {
            ret = ICE_CONTROLLER_RESULT_FAIL_MQ_SEND;
        }
    }

    return ret;
}

IceControllerResult_t IceControllerNet_HandleRxPacket( IceControllerContext_t * pCtx,
                                                       IceControllerSocketContext_t * pSocketContext )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    IceHandleStunPacketResult_t iceHandleStunResult;
    int readBytes;
    struct sockaddr srcAddress;
    socklen_t srcAddressLength = sizeof( srcAddress );
    uint8_t * pTransactionIdBuffer;
    struct sockaddr_in * pIpv4Address;
    struct sockaddr_in6 * pIpv6Address;
    IceEndpoint_t remoteIceEndpoint;
    IceCandidatePair_t * pCandidatePair = NULL;
    uint8_t sentStunBuffer[ ICE_CONTROLLER_STUN_MESSAGE_BUFFER_SIZE ];
    size_t sentStunBufferLength = ICE_CONTROLLER_STUN_MESSAGE_BUFFER_SIZE;
    char ipBuffer[ INET_ADDRSTRLEN ];
    char ipBuffer2[ INET_ADDRSTRLEN ];

    readBytes = recvfrom( pSocketContext->socketFd, receiveBuffer, RX_BUFFER_SIZE, 0, &srcAddress, &srcAddressLength );
    if( readBytes < 0 )
    {
        if( ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) )
        {
            /* Timeout, no more data to receive. */
            ret = ICE_CONTROLLER_RESULT_NO_MORE_RX_PACKET;
        }
        else
        {
            LogError( ( "Fail to receive packets from socket ID: %d, errno: %s", pSocketContext->socketFd, strerror( errno ) ) );
            ret = ICE_CONTROLLER_RESULT_FAIL_RECVFROM;
        }
    }
    else if( readBytes == 0 )
    {
        /* Nothing to do if receive 0 byte. */
        ret = ICE_CONTROLLER_RESULT_NO_MORE_RX_PACKET;
    }
    else
    {
        /* Received data, handle this STUN message. */
        if( srcAddress.sa_family == AF_INET )
        {
            pIpv4Address = ( struct sockaddr_in * ) &srcAddress;

            remoteIceEndpoint.transportAddress.family = STUN_ADDRESS_IPv4;
            remoteIceEndpoint.transportAddress.port = ntohs( pIpv4Address->sin_port );
            memcpy( remoteIceEndpoint.transportAddress.address, &pIpv4Address->sin_addr, STUN_IPV4_ADDRESS_SIZE );
        }
        else if( srcAddress.sa_family == AF_INET6 )
        {
            pIpv6Address = ( struct sockaddr_in6 * ) &srcAddress;

            remoteIceEndpoint.transportAddress.family = STUN_ADDRESS_IPv6;
            remoteIceEndpoint.transportAddress.port = ntohs( pIpv6Address->sin6_port );
            memcpy( remoteIceEndpoint.transportAddress.address, &pIpv6Address->sin6_addr, STUN_IPV6_ADDRESS_SIZE );
        }
        else
        {
            /* Unknown IP type, drop packet. */
            ret = ICE_CONTROLLER_RESULT_INVALID_RX_PACKET_FAMILY;
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        LogDebug( ( "Receiving %d bytes from IP/port: %s/%d", readBytes,
                    IceControllerNet_LogIpAddressInfo( &remoteIceEndpoint, ipBuffer, sizeof( ipBuffer ) ),
                    remoteIceEndpoint.transportAddress.port ) );
        IceControllerNet_LogStunPacket( receiveBuffer, readBytes );

        iceHandleStunResult = Ice_HandleStunPacket( &pSocketContext->pRemoteInfo->iceContext,
                                                    receiveBuffer,
                                                    ( size_t ) readBytes,
                                                    &pSocketContext->pLocalCandidate->endpoint,
                                                    &remoteIceEndpoint,
                                                    &pTransactionIdBuffer,
                                                    &pCandidatePair );

        switch( iceHandleStunResult )
        {
        case ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_SERVER_REFLEXIVE_CANDIDATE_ADDRESS:
            if( sendIceCandidate( pCtx, pSocketContext->pLocalCandidate, pSocketContext->pRemoteInfo ) != ICE_CONTROLLER_RESULT_OK )
            {
                /* Just ignore this failing case and continue the ICE procedure. */
                LogWarn( ( "Fail to send server reflexive candidate to remote peer, result" ) );
            }

            pCtx->metrics.pendingSrflxCandidateNum--;
            if( pCtx->metrics.pendingSrflxCandidateNum == 0 )
            {
                gettimeofday( &pCtx->metrics.allSrflxCandidateReadyTime, NULL );
            }
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK:
        case ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION:
        case ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST:
            if( Ice_CreateResponseForRequest( &pSocketContext->pRemoteInfo->iceContext,
                                              pCandidatePair,
                                              pTransactionIdBuffer,
                                              sentStunBuffer,
                                              &sentStunBufferLength ) != ICE_RESULT_OK )
            {
                LogWarn( ( "Unable to create STUN response for nomination" ) );
            }
            else
            {
                LogDebug( ( "Sending STUN bind response back to remote" ) );
                IceControllerNet_LogStunPacket( sentStunBuffer, sentStunBufferLength );

                if( IceControllerNet_SendPacket( pSocketContext, &pCandidatePair->pRemoteCandidate->endpoint, sentStunBuffer, sentStunBufferLength ) != ICE_CONTROLLER_RESULT_OK )
                {
                    LogWarn( ( "Unable to send STUN response for nomination" ) );
                }
                else
                {
                    LogDebug( ( "Sent STUN bind response back to remote" ) );
                    if( iceHandleStunResult == ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION )
                    {
                        LogInfo( ( "Sent nominating STUN bind response" ) );
                        LogDebug( ( "Candidiate pair is nominated, local IP/port: %s/%u, remote IP/port: %s/%u",
                                    IceControllerNet_LogIpAddressInfo( &pCandidatePair->pLocalCandidate->endpoint, ipBuffer, sizeof( ipBuffer ) ), pCandidatePair->pLocalCandidate->endpoint.transportAddress.port,
                                    IceControllerNet_LogIpAddressInfo( &pCandidatePair->pRemoteCandidate->endpoint, ipBuffer2, sizeof( ipBuffer2 ) ), pCandidatePair->pRemoteCandidate->endpoint.transportAddress.port ) );
                        gettimeofday( &pCtx->metrics.sentNominationResponseTime, NULL );
                        if( TIMER_CONTROLLER_RESULT_SET == TimerController_IsTimerSet( &pCtx->connectivityCheckTimer ) )
                        {
                            TimerController_ResetTimer( &pCtx->connectivityCheckTimer );
                            IceController_PrintMetrics( pCtx );
                            ( void ) IceControllerSocketListener_StopPolling( pCtx );
                        }
                        ret = ICE_CONTROLLER_RESULT_FOUND_CONNECTION;
                        pSocketContext->pRemoteInfo->pNominationPair = pCandidatePair;
                    }
                }
            }
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION:
            LogInfo( ( "ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR:
            LogInfo( ( "A valid candidate pair is found" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY:
            LogInfo( ( "ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_INTEGRITY_MISMATCH:
            LogWarn( ( "Message Integrity check of the received packet failed" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH:
            LogWarn( ( "FingerPrint check of the received packet failed" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_INVALID_PACKET_TYPE:
            LogWarn( ( "Invalid Type of Packet received" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND:
            LogError( ( "Error : Valid Candidate Pair is not found" ) );
            break;
        case ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_NOT_FOUND:
            LogError( ( "Error : Valid Server Reflexive Candidate is not found" ) );
            break;
        default:
            LogWarn( ( "Unknown case: %d", iceHandleStunResult ) );
            break;
        }
    }


    return ret;
}

IceControllerResult_t IceControllerNet_DnsLookUp( char * pUrl,
                                                  IceTransportAddress_t * pIceTransportAddress )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    int dnsResult;
    struct addrinfo * pResult = NULL;
    struct addrinfo * pIterator;
    struct sockaddr_in * ipv4Address;
    struct sockaddr_in6 * ipv6Address;

    if( ( pUrl == NULL ) || ( pIceTransportAddress == NULL ) )
    {
        ret = ICE_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        dnsResult = getaddrinfo( pUrl, NULL, NULL, &pResult );
        if( dnsResult != 0 )
        {
            LogWarn( ( "DNS query failing, url: %s, result: %d", pUrl, dnsResult ) );
            ret = ICE_CONTROLLER_RESULT_FAIL_DNS_QUERY;
        }
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        for( pIterator = pResult; pIterator; pIterator = pIterator->ai_next )
        {
            if( pIterator->ai_family == AF_INET )
            {
                ipv4Address = ( struct sockaddr_in * ) pIterator->ai_addr;
                pIceTransportAddress->family = STUN_ADDRESS_IPv4;
                memcpy( pIceTransportAddress->address, &ipv4Address->sin_addr, STUN_IPV4_ADDRESS_SIZE );
                break;
            }
            else if( pIterator->ai_family == AF_INET6 )
            {
                ipv6Address = ( struct sockaddr_in6 * ) pIterator->ai_addr;
                pIceTransportAddress->family = STUN_ADDRESS_IPv6;
                memcpy( pIceTransportAddress->address, &ipv6Address->sin6_addr, STUN_IPV6_ADDRESS_SIZE );
                break;
            }
        }
    }

    if( pResult )
    {
        freeaddrinfo( pResult );
    }

    return ret;
}

const char * IceControllerNet_LogIpAddressInfo( const IceEndpoint_t * pIceEndpoint,
                                                char * pIpBuffer,
                                                size_t ipBufferLength )
{
    const char * ret = ICE_CONTROLLER_STUN_MESSAGE_TYPE_STRING_UNKNOWN;

    if( ( pIceEndpoint != NULL ) && ( pIpBuffer != NULL ) && ( ipBufferLength >= INET_ADDRSTRLEN ) )
    {
        ret = inet_ntop( AF_INET, pIceEndpoint->transportAddress.address, pIpBuffer, ipBufferLength );
    }

    return ret;
}

void IceControllerNet_LogStunPacket( uint8_t * pStunPacket,
                                     size_t stunPacketSize )
{
    IceControllerStunMsgHeader_t * pStunMsgHeader = ( IceControllerStunMsgHeader_t * ) pStunPacket;

    if( ( pStunPacket == NULL ) || ( stunPacketSize < sizeof( IceControllerStunMsgHeader_t ) ) )
    {
        // invalid STUN packet, ignore it
    }
    else
    {
        LogDebug( ( "Dumping STUN packets: STUN type: %s, content length:: 0x%02x%02x, transaction ID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                    convertStunMsgTypeToString( pStunMsgHeader->msgType ),
                    pStunMsgHeader->contentLength[0], pStunMsgHeader->contentLength[1],
                    pStunMsgHeader->transactionId[0], pStunMsgHeader->transactionId[1], pStunMsgHeader->transactionId[2], pStunMsgHeader->transactionId[3],
                    pStunMsgHeader->transactionId[4], pStunMsgHeader->transactionId[5], pStunMsgHeader->transactionId[6], pStunMsgHeader->transactionId[7],
                    pStunMsgHeader->transactionId[8], pStunMsgHeader->transactionId[9], pStunMsgHeader->transactionId[10], pStunMsgHeader->transactionId[11] ) );
    }
}
