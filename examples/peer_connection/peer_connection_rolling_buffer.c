#include <stdlib.h>
#include "logging.h"
#include "peer_connection.h"
#include "peer_connection_rolling_buffer.h"

#include "FreeRTOS.h"

PeerConnectionResult_t PeerConnectionRollingBuffer_Create( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                           uint32_t rollingbufferBitRate,  // bps
                                                           uint32_t rollingbufferDurationSec,  // duration in seconds
                                                           size_t maxSizePerPacket )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpPacketInfo_t * pRtpPacketInfoArray;
    RtpPacketQueueResult_t resultRtpPacketQueue;

    if( ( pRollingBuffer == NULL ) ||
        ( rollingbufferBitRate == 0 ) ||
        ( rollingbufferDurationSec == 0 ) ||
        ( maxSizePerPacket == 0 ) )
    {
        LogError( ( "Invalid input, pRollingBuffer: %p, rollingbufferBitRate: %lu, pFrame: %lu, maxSizePerPacket: %u",
                    pRollingBuffer,
                    rollingbufferBitRate,
                    rollingbufferDurationSec,
                    maxSizePerPacket ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pRollingBuffer->maxSizePerPacket = maxSizePerPacket;
        pRollingBuffer->capacity = rollingbufferDurationSec * rollingbufferBitRate / 8U / maxSizePerPacket;
        pRtpPacketInfoArray = ( RtpPacketInfo_t * )pvPortMalloc( pRollingBuffer->capacity * sizeof( RtpPacketInfo_t ) );
        if( pRtpPacketInfoArray == NULL )
        {
            LogError( ( "No memory available for allocating RTP packet info array with total size %u, capacity: %u, sizeof( RtpPacketInfo_t ): %u",
                        pRollingBuffer->capacity * sizeof( RtpPacketInfo_t ),
                        pRollingBuffer->capacity,
                        sizeof( RtpPacketInfo_t ) ) );
            ret = PEER_CONNECTION_RESULT_FAIL_PACKET_INFO_NO_ENOUGH_MEMORY;
        }
        else
        {
            LogDebug( ( "Allocated RTP packet info array with total size %u, capacity: %u, sizeof( RtpPacketInfo_t ): %u",
                        pRollingBuffer->capacity * sizeof( RtpPacketInfo_t ),
                        pRollingBuffer->capacity,
                        sizeof( RtpPacketInfo_t ) ) );
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultRtpPacketQueue = RtpPacketQueue_Init( &pRollingBuffer->packetQueue,
                                                    pRtpPacketInfoArray,
                                                    pRollingBuffer->capacity );
        if( resultRtpPacketQueue != RTP_PACKET_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to init RTP packet queue with result: %d", resultRtpPacketQueue ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_QUEUE_INIT;
        }
    }

    return ret;
}

void PeerConnectionRollingBuffer_Free( PeerConnectionRollingBuffer_t * pRollingBuffer )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpPacketQueueResult_t resultRtpPacketQueue = RTP_PACKET_QUEUE_RESULT_OK;
    RtpPacketInfo_t rtpPacketInfo;

    if( pRollingBuffer == NULL )
    {
        LogError( ( "Invalid input, pRollingBuffer: %p",
                    pRollingBuffer ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        while( resultRtpPacketQueue == RTP_PACKET_QUEUE_RESULT_OK )
        {
            resultRtpPacketQueue = RtpPacketQueue_Dequeue( &pRollingBuffer->packetQueue,
                                                           &rtpPacketInfo );
            if( ( resultRtpPacketQueue == RTP_PACKET_QUEUE_RESULT_OK ) && ( rtpPacketInfo.pSerializedRtpPacket != NULL ) )
            {
                vPortFree( rtpPacketInfo.pSerializedRtpPacket );
            }
        }

        if( pRollingBuffer->packetQueue.pRtpPacketInfoArray != NULL )
        {
            vPortFree( pRollingBuffer->packetQueue.pRtpPacketInfoArray );
        }
    }
}

PeerConnectionResult_t PeerConnectionRollingBuffer_GetRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                                         uint16_t rtpSeq,
                                                                         uint8_t ** ppBuffer,
                                                                         size_t * pBufferLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;

    if( ( pRollingBuffer == NULL ) ||
        ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) )
    {
        LogError( ( "Invalid input, pRollingBuffer: %p, ppBuffer: %p, pBufferLength: %p",
                    pRollingBuffer, ppBuffer, pBufferLength ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else if( pRollingBuffer->capacity == 0 )
    {
        LogError( ( "Rolling buffer is not initialized yet." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else
    {
        *ppBuffer = ( uint8_t * )pvPortMalloc( pRollingBuffer->maxSizePerPacket );
        *pBufferLength = pRollingBuffer->maxSizePerPacket;
    }

    return ret;
}

void PeerConnectionRollingBuffer_DiscardRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                           uint8_t * pBuffer )
{
    ( void ) pRollingBuffer;
    if( pBuffer )
    {
        vPortFree( pBuffer );
    }
}

PeerConnectionResult_t PeerConnectionRollingBuffer_SearchRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                                            uint16_t rtpSeq,
                                                                            uint8_t ** ppBuffer,
                                                                            size_t * pBufferLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpPacketQueueResult_t resultRtpPacketQueue = RTP_PACKET_QUEUE_RESULT_OK;
    RtpPacketInfo_t rtpPacketInfo;

    if( ( pRollingBuffer == NULL ) ||
        ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) )
    {
        LogError( ( "Invalid input, pRollingBuffer: %p, ppBuffer: %p, pBufferLength: %p",
                    pRollingBuffer, ppBuffer, pBufferLength ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else if( pRollingBuffer->capacity == 0 )
    {
        LogError( ( "Rolling buffer is not initialized yet." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else
    {
        /* Empty else marker. */
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultRtpPacketQueue = RtpPacketQueue_Retrieve( &pRollingBuffer->packetQueue,
                                                        rtpSeq,
                                                        &rtpPacketInfo );
        if( resultRtpPacketQueue != RTP_PACKET_QUEUE_RESULT_OK )
        {
            LogError( ( "Fail to retrieve RTP packet sequence number: %u with result: %d",
                        rtpSeq,
                        resultRtpPacketQueue ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_QUEUE_RETRIEVE;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        *ppBuffer = rtpPacketInfo.pSerializedRtpPacket;
        *pBufferLength = rtpPacketInfo.serializedPacketLength;
    }

    return ret;
}

PeerConnectionResult_t PeerConnectionRollingBuffer_SetPacket( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                              uint16_t rtpSeq,
                                                              uint8_t * pBuffer,
                                                              size_t bufferLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpPacketQueueResult_t resultRtpPacketQueue = RTP_PACKET_QUEUE_RESULT_OK;
    RtpPacketInfo_t rtpPacket, deletedRtpPacket;

    if( pRollingBuffer == NULL )
    {
        LogError( ( "Invalid input, pRollingBuffer: %p",
                    pRollingBuffer ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else if( pRollingBuffer->capacity == 0 )
    {
        LogError( ( "Rolling buffer is not initialized yet." ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }
    else
    {
        /* Empty else marker. */
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( &rtpPacket, 0, sizeof( RtpPacketInfo_t ) );
        memset( &deletedRtpPacket, 0, sizeof( RtpPacketInfo_t ) );
        rtpPacket.pSerializedRtpPacket = pBuffer;
        rtpPacket.seqNum = rtpSeq;
        rtpPacket.serializedPacketLength = bufferLength;
        resultRtpPacketQueue = RtpPacketQueue_ForceEnqueue( &pRollingBuffer->packetQueue,
                                                            &rtpPacket,
                                                            &deletedRtpPacket );
        if( ( resultRtpPacketQueue != RTP_PACKET_QUEUE_RESULT_OK ) && ( resultRtpPacketQueue != RTP_PACKET_QUEUE_RESULT_PACKET_DELETED ) )
        {
            LogError( ( "Fail to enqueue RTP packet sequence number: %u with result: %d",
                        rtpSeq,
                        resultRtpPacketQueue ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_ENQUEUE;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( deletedRtpPacket.pSerializedRtpPacket )
        {
            vPortFree( deletedRtpPacket.pSerializedRtpPacket );
        }
    }

    return ret;
}
