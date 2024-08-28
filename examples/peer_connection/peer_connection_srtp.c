#include <stdlib.h>
#include "logging.h"
#include "peer_connection.h"
#include "peer_connection_srtp.h"
#include "peer_connection_rolling_buffer.h"

/* API includes. */
#include "rtp_api.h"
#include "rtcp_api.h"
#include "h264_packetizer.h"
#include "ice_controller.h"

#define PEER_CONNECTION_SRTP_H264_MAX_NALUS_IN_A_FRAME        ( 64 )
#define PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH      ( 1200 )

#define PEER_CONNECTION_SRTP_VIDEO_CLOCKRATE ( uint32_t ) 90000
#define PEER_CONNECTION_SRTP_OPUS_CLOCKRATE  ( uint32_t ) 48000
#define PEER_CONNECTION_SRTP_PCM_CLOCKRATE   ( uint32_t ) 8000

#define PEER_CONNECTION_SRTP_US_IN_A_SECOND ( 1000000 )
#define PEER_CONNECTION_SRTP_CONVERT_TIME_US_TO_RTP_TIMESTAMP( clockRate, presentationUs ) ( uint32_t )( ( ( ( presentationUs ) * ( clockRate ) ) / PEER_CONNECTION_SRTP_US_IN_A_SECOND ) & 0xFFFFFFFF )

/*
 *
     0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |       0xBE    |    0xDE       |           length=1            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  ID   | L=1   |transport-wide sequence number | zero padding  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
// https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
#define PEER_CONNECTION_SRTP_TWCC_EXT_PROFILE ( 0xBEDE )
#define PEER_CONNECTION_SRTP_GET_TWCC_PAYLOAD( extId, sequenceNum ) ( ( ( ( extId ) & 0xfu ) << 28u ) | ( 1u << 24u ) | ( ( uint32_t ) ( sequenceNum ) << 8u ) )

#define PEER_CONNECTION_SRTCP_NACK_MAX_SEQ_NUM ( 128 )

static PeerConnectionResult_t ConstructSrtpPacket( PeerConnectionSession_t * pSession,
                                                   const Transceiver_t * pTransceiver,
                                                   uint8_t * pRtpPayload,
                                                   size_t rtpPayloadLength,
                                                   uint8_t isLastPacket,
                                                   uint32_t rtpTimestamp,
                                                   uint8_t * pOutputSrtpPacket,
                                                   size_t * pOutputSrtpPacketLength,
                                                   RtpPacket_t * pPacketRtp,
                                                   uint32_t payloadType,
                                                   uint16_t rtpSeq,
                                                   uint32_t ssrc )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpResult_t resultRtp;
    size_t srtpBufferLength;
    srtp_err_status_t errorStatus;
    /* For TWCC ID extension info. */
    uint32_t extensionPayload;

    if( ( pSession == NULL ) ||
        ( pRtpPayload == NULL ) ||
        ( pOutputSrtpPacket == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pOutputSrtpPacketLength == NULL ) ||
        ( pPacketRtp == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pRtpPayload: %p, pOutputSrtpPacket: %p, pOutputSrtpPacketLength: %p, pTransceiver: %p",
                    pSession,
                    pRtpPayload,
                    pOutputSrtpPacket,
                    pOutputSrtpPacketLength,
                    pTransceiver ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Take sender mutex and initialize some variables for RTP for efficiency. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( pPacketRtp, 0, sizeof( RtpPacket_t ) );
        pPacketRtp->header.payloadType = payloadType;
        pPacketRtp->header.sequenceNumber = rtpSeq;
        pPacketRtp->header.ssrc = ssrc;
        if( isLastPacket )
        {
            /* This is the last packet, set the marker. */
            pPacketRtp->header.flags |= RTP_HEADER_FLAG_MARKER;
        }
    }

    /* Get buffer from sender for serializing RTP packet */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        srtpBufferLength = *pOutputSrtpPacketLength;
    }

    /* Contruct RTP packet for each payload buffer. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pPacketRtp->header.csrcCount = 0;
        pPacketRtp->header.pCsrc = NULL;
        pPacketRtp->header.timestamp = rtpTimestamp;

        if( pSession->rtpConfig.twccId > 0 )
        {
            pPacketRtp->header.flags |= RTP_HEADER_FLAG_EXTENSION;
            pPacketRtp->header.extension.extensionProfile = PEER_CONNECTION_SRTP_TWCC_EXT_PROFILE;
            pPacketRtp->header.extension.extensionPayloadLength = 1;
            extensionPayload = PEER_CONNECTION_SRTP_GET_TWCC_PAYLOAD( pSession->rtpConfig.twccId, pSession->rtpConfig.twccSequence );
            pPacketRtp->header.extension.pExtensionPayload = &extensionPayload;
            pSession->rtpConfig.twccSequence++;
        }

        pPacketRtp->payloadLength = rtpPayloadLength;
        pPacketRtp->pPayload = pRtpPayload;

        resultRtp = Rtp_Serialize( &pSession->pCtx->rtpContext,
                                   pPacketRtp,
                                   pOutputSrtpPacket,
                                   pOutputSrtpPacketLength );
        if( resultRtp != RTP_RESULT_OK )
        {
            LogError( ( "Fail to serialize RTP packet, result: %d", resultRtp ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTP_SERIALIZE;
        }
    }

    /* Encrypt it by SRTP. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        errorStatus = srtp_protect( pSession->srtpTransmitSession, pOutputSrtpPacket, *pOutputSrtpPacketLength, pOutputSrtpPacket, &srtpBufferLength, 0 );
        if( errorStatus != srtp_err_status_ok )
        {
            LogError( ( "Fail to encrypt Tx SRTP packet, errorStatus: %d, seq: %u", errorStatus, rtpSeq ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ENCRYPT_SRTP_RTP_PACKET;
        }
        else
        {
            *pOutputSrtpPacketLength = srtpBufferLength;
        }
    }

    return ret;
}

static PeerConnectionResult_t ResendSrtpPacket( PeerConnectionSession_t * pSession,
                                                const Transceiver_t * pTransceiver,
                                                uint16_t rtpSeq,
                                                uint32_t ssrc )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    PeerConnectionSrtpSender_t * pSrtpSender = NULL;
    uint8_t isLocked = 0;
    PeerConnectionRollingBufferPacket_t * pRollingBufferPacket = NULL;
    IceControllerResult_t resultIceController;
    uint8_t bufferAfterEncrypt = 1;
    uint8_t srtpBuffer[ PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH ];
    uint8_t * pSrtpPacket = NULL;
    size_t srtpPacketLength = 0;
    uint32_t payloadType;
    uint16_t * pRtpSeq = NULL;

    if( ( pSession == NULL ) || ( pTransceiver == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pTransceiver: %p", pSession, pTransceiver ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pRtpSeq = &rtpSeq;
        if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
        {
            pSrtpSender = &pSession->videoSrtpSender;
            payloadType = pSession->rtpConfig.videoCodecPayload;
            if( ( pSession->rtpConfig.videoCodecRtxPayload != 0 ) &&
                ( pSession->rtpConfig.videoCodecRtxPayload != pSession->rtpConfig.videoCodecPayload ) )
            {
                bufferAfterEncrypt = 0;
                payloadType = pSession->rtpConfig.videoCodecRtxPayload;
                pRtpSeq = &pSession->rtpConfig.videoRtxSequenceNumber;
            }
        }
        else
        {
            pSrtpSender = &pSession->audioSrtpSender;
            payloadType = pSession->rtpConfig.audioCodecPayload;
            if( ( pSession->rtpConfig.audioCodecRtxPayload != 0 ) &&
                ( pSession->rtpConfig.audioCodecRtxPayload != pSession->rtpConfig.audioCodecPayload ) )
            {
                bufferAfterEncrypt = 0;
                payloadType = pSession->rtpConfig.audioCodecRtxPayload;
                pRtpSeq = &pSession->rtpConfig.audioRtxSequenceNumber;
            }
        }

        /* Lock sender. */
        if( xSemaphoreTake( pSrtpSender->senderMutex, portMAX_DELAY ) == pdTRUE )
        {
            isLocked = 1;
        }
        else
        {
            LogError( ( "Fail to take sender mutex" ) );
            ret = PEER_CONNECTION_RESULT_FAIL_TAKE_SENDER_MUTEX;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        ret = PeerConnectionRollingBuffer_GetRtpSequenceBuffer( &pSrtpSender->txRollingBuffer,
                                                                rtpSeq,
                                                                &pRollingBufferPacket );
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        if( bufferAfterEncrypt == 0 )
        {
            pSrtpPacket = srtpBuffer;
            srtpPacketLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;
            ret = ConstructSrtpPacket( pSession,
                                       pTransceiver,
                                       pRollingBufferPacket->pPacketBuffer,
                                       pRollingBufferPacket->packetBufferLength,
                                       pRollingBufferPacket->rtpPacket.header.flags & RTP_HEADER_FLAG_MARKER,
                                       pRollingBufferPacket->rtpPacket.header.timestamp,
                                       pSrtpPacket,
                                       &srtpPacketLength,
                                       &pRollingBufferPacket->rtpPacket,
                                       payloadType,
                                       ( *pRtpSeq )++,
                                       ssrc );
        }
        else
        {
            pSrtpPacket = pRollingBufferPacket->pPacketBuffer;
            srtpPacketLength = pRollingBufferPacket->packetBufferLength;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultIceController = IceController_SendToRemotePeer( &pSession->iceControllerContext,
                                                              pSrtpPacket,
                                                              srtpPacketLength );
        if( resultIceController != ICE_CONTROLLER_RESULT_OK )
        {
            LogWarn( ( "Fail to re-send RTP packet, ret: %d, seq: %u, SSRC: 0x%lx", resultIceController, rtpSeq - 1, ssrc ) );
            ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_RESEND_RTP_PACKET;
        }
        else
        {
            LogDebug( ( "Re-send RTP successfully, RTP seq: %u, SSRC: 0x%lx", rtpSeq - 1, ssrc ) );
        }
    }

    if( isLocked )
    {
        xSemaphoreGive( pSrtpSender->senderMutex );
    }

    return ret;
}

static PeerConnectionResult_t OnRtcpNackEvent( PeerConnectionSession_t * pSession,
                                               RtcpPacket_t * pRtcpPacket )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtcpResult_t resultRtcp;
    RtcpNackPacket_t nackPacket;
    const Transceiver_t * pTransceiver = NULL;
    uint16_t seqNumList[ PEER_CONNECTION_SRTCP_NACK_MAX_SEQ_NUM ];
    int i;

    if( ( pSession == NULL ) || ( pRtcpPacket == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pRtcpPacket: %p", pSession, pRtcpPacket ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    for( i = 0; i < pRtcpPacket->payloadLength; i += 4 )
    {
        if( i + 3 < pRtcpPacket->payloadLength )
        {
            LogDebug( ( "Dumping whole RTCP NACK packet: 0x%x 0x%x 0x%x 0x%x",
                        pRtcpPacket->pPayload[i],pRtcpPacket->pPayload[i + 1],pRtcpPacket->pPayload[i + 2],pRtcpPacket->pPayload[i + 3] ) );
        }
        else if( i + 2 < pRtcpPacket->payloadLength )
        {
            LogDebug( ( "Dumping whole RTCP NACK packet: 0x%x 0x%x 0x%x",
                        pRtcpPacket->pPayload[i],pRtcpPacket->pPayload[i + 1],pRtcpPacket->pPayload[i + 2] ) );
        }
        else if( i + 1 < pRtcpPacket->payloadLength )
        {
            LogDebug( ( "Dumping whole RTCP NACK packet: 0x%x 0x%x",
                        pRtcpPacket->pPayload[i],pRtcpPacket->pPayload[i + 1] ) );
        }
        else
        {
            LogDebug( ( "Dumping whole RTCP NACK packet: 0x%x",
                        pRtcpPacket->pPayload[i] ) );
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( &nackPacket, 0, sizeof( RtcpNackPacket_t ) );
        memset( &seqNumList, 0, sizeof( seqNumList ) );
        nackPacket.pSeqNumList = seqNumList;
        nackPacket.seqNumListLength = PEER_CONNECTION_SRTCP_NACK_MAX_SEQ_NUM;
        resultRtcp = Rtcp_ParseNackPacket( &pSession->pCtx->rtcpContext,
                                           pRtcpPacket,
                                           &nackPacket );
        if( resultRtcp != RTCP_RESULT_OK )
        {
            LogError( ( "Fail to parse RTCP NACK packet, result: %d", resultRtcp ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTCP_PARSE_NACK;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        ret = PeerConnection_MatchTransceiverBySsrc( pSession->pCtx,
                                                     nackPacket.mediaSourceSsrc,
                                                     &pTransceiver );
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        for( i = 0; i < nackPacket.seqNumListLength; i++ )
        {
            /* Retransmit matching sequence number one by one. */
            ret = ResendSrtpPacket( pSession, pTransceiver, nackPacket.pSeqNumList[i], nackPacket.senderSsrc );
            if( ret != PEER_CONNECTION_RESULT_OK )
            {
                break;
            }
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnectionSrtp_Init( PeerConnectionSession_t * pSession )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    srtp_policy_t receivePolicy, transmitPolicy;
    void (* srtp_policy_setter)( srtp_crypto_policy_t * ) = NULL;
    void (* srtcp_policy_setter)( srtp_crypto_policy_t * ) = NULL;
    srtp_err_status_t errorStatus;
    PeerConnectionSrtpSender_t * pSrtpSender = NULL;
    int i;
    size_t maxSizePerPacket = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;

    if( pSession == NULL )
    {
        LogError( ( "Invalid input, pSession: %p", pSession ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        switch( pSession->dtlsSession.xNetworkCredentials.dtlsKeyingMaterial.srtpProfile )
        {
            case KVS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80:
                srtp_policy_setter = srtp_crypto_policy_set_rtp_default;
                srtcp_policy_setter = srtp_crypto_policy_set_rtp_default;
                break;
            case KVS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_32:
                srtp_policy_setter = srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32;
                srtcp_policy_setter = srtp_crypto_policy_set_rtp_default;
                break;
            default:
                LogError( ( "Unknown SRTP profile: %d", pSession->dtlsSession.xNetworkCredentials.dtlsKeyingMaterial.srtpProfile ) );
                ret = PEER_CONNECTION_RESULT_UNKNOWN_SRTP_PROFILE;
                break;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( &receivePolicy, 0, sizeof( receivePolicy ) );
        srtp_policy_setter( &receivePolicy.rtp );
        srtcp_policy_setter( &receivePolicy.rtcp );

        receivePolicy.key = pSession->dtlsSession.xNetworkCredentials.dtlsKeyingMaterial.serverWriteKey;
        receivePolicy.ssrc.type = ssrc_any_inbound;
        receivePolicy.next = NULL;

        errorStatus = srtp_create( &( pSession->srtpReceiveSession ), &receivePolicy );
        if( errorStatus != srtp_err_status_ok )
        {
            LogError( ( "Fail to create Rx SRTP session, errorStatus: %d", errorStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_SRTP_RX_SESSION;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        memset( &transmitPolicy, 0, sizeof( transmitPolicy ) );
        srtp_policy_setter( &transmitPolicy.rtp );
        srtcp_policy_setter( &transmitPolicy.rtcp );

        transmitPolicy.key = pSession->dtlsSession.xNetworkCredentials.dtlsKeyingMaterial.clientWriteKey;
        transmitPolicy.ssrc.type = ssrc_any_outbound;
        transmitPolicy.next = NULL;

        errorStatus = srtp_create( &( pSession->srtpTransmitSession ), &transmitPolicy );
        if( errorStatus != srtp_err_status_ok )
        {
            LogError( ( "Fail to create Tx SRTP session, errorStatus: %d", errorStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_CREATE_SRTP_TX_SESSION;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        /* Initialize Rolling buffers */
        for( i = 0; i < pSession->pCtx->transceiverCount; i++ )
        {
            if( pSession->pCtx->pTransceivers[i]->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
            {
                pSrtpSender = &pSession->videoSrtpSender;
                if( ( pSession->rtpConfig.videoCodecRtxPayload != 0 ) &&
                    ( pSession->rtpConfig.videoCodecRtxPayload != pSession->rtpConfig.videoCodecPayload ) )
                {
                    /* If we're using different payload type in re-transmission, we create the rolling buffer just for RTP payload. */
                    maxSizePerPacket = PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH;
                }
                ret = PeerConnectionRollingBuffer_Create( &pSession->videoSrtpSender.txRollingBuffer,
                                                          pSession->pCtx->pTransceivers[i]->rollingbufferBitRate, // bps
                                                          pSession->pCtx->pTransceivers[i]->rollingbufferDurationSec, // duration in seconds
                                                          maxSizePerPacket );
            }
            else
            {
                pSrtpSender = &pSession->audioSrtpSender;
                if( ( pSession->rtpConfig.audioCodecRtxPayload != 0 ) &&
                    ( pSession->rtpConfig.audioCodecRtxPayload != pSession->rtpConfig.audioCodecPayload ) )
                {
                    /* If we're using different payload type in re-transmission, we create the rolling buffer just for RTP payload. */
                    maxSizePerPacket = PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH;
                }
                ret = PeerConnectionRollingBuffer_Create( &pSession->audioSrtpSender.txRollingBuffer,
                                                          pSession->pCtx->pTransceivers[i]->rollingbufferBitRate, // bps
                                                          pSession->pCtx->pTransceivers[i]->rollingbufferDurationSec, // duration in seconds
                                                          maxSizePerPacket );
            }

            if( ret != PEER_CONNECTION_RESULT_OK )
            {
                break;
            }

            /* Mutex can only be created in executing scheduler. */
            pSrtpSender->senderMutex = xSemaphoreCreateMutex();
            if( pSrtpSender->senderMutex == NULL )
            {
                LogError( ( "Fail to create mutex for SRTP sender." ) );
                ret = PEER_CONNECTION_RESULT_FAIL_CREATE_SENDER_MUTEX;
                break;
            }
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnectionSrtp_WriteH264Frame( PeerConnectionSession_t * pSession,
                                                          Transceiver_t * pTransceiver,
                                                          const PeerConnectionFrame_t * pFrame )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    H264PacketizerContext_t h264PacketizerContext;
    H264Result_t resultH264;
    H264Packet_t packetH264;
    uint8_t rtpBuffer[ PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH ];
    PeerConnectionRollingBufferPacket_t * pRollingBufferPacket = NULL;
    uint8_t * pSrtpPacket = NULL;
    size_t srtpPacketLength = 0;
    Nalu_t nalusArray[ PEER_CONNECTION_SRTP_H264_MAX_NALUS_IN_A_FRAME ];
    Frame_t h264Frame;
    PeerConnectionSrtpSender_t * pSrtpSender = NULL;
    uint8_t isLocked = 0;
    uint8_t bufferAfterEncrypt = 1;
    IceControllerResult_t resultIceController;
    uint16_t * pRtpSeq = NULL;
    uint32_t payloadType;
    uint32_t * pSsrc = NULL;

    if( ( pSession == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pFrame == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pTransceiver: %p, pFrame: %p",
                    pSession, pTransceiver, pFrame ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultH264 = H264Packetizer_Init( &h264PacketizerContext,
                                          nalusArray,
                                          PEER_CONNECTION_SRTP_H264_MAX_NALUS_IN_A_FRAME );
        if( resultH264 != H264_RESULT_OK )
        {
            LogError( ( "Fail to init H264 packetizer, result: %d", resultH264 ) );
            ret = PEER_CONNECTION_RESULT_FAIL_PACKETIZER_INIT;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        h264Frame.pFrameData = pFrame->pData;
        h264Frame.frameDataLength = pFrame->dataLength;
        resultH264 = H264Packetizer_AddFrame( &h264PacketizerContext,
                                              &h264Frame );
        if( resultH264 != H264_RESULT_OK )
        {
            LogError( ( "Fail to init H264 packetizer, result: %d", resultH264 ) );
            ret = PEER_CONNECTION_RESULT_FAIL_PACKETIZER_ADD_FRAME;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        pSsrc = &pTransceiver->ssrc;
        if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
        {
            pSrtpSender = &pSession->videoSrtpSender;
            pRtpSeq = &pSession->rtpConfig.videoSequenceNumber;
            payloadType = pSession->rtpConfig.videoCodecPayload;
            if( ( pSession->rtpConfig.videoCodecRtxPayload != 0 ) &&
                ( pSession->rtpConfig.videoCodecRtxPayload != pSession->rtpConfig.videoCodecPayload ) )
            {
                bufferAfterEncrypt = 0;
            }
        }
        else
        {
            pSrtpSender = &pSession->audioSrtpSender;
            pRtpSeq = &pSession->rtpConfig.audioSequenceNumber;
            payloadType = pSession->rtpConfig.audioCodecPayload;
            if( ( pSession->rtpConfig.audioCodecRtxPayload != 0 ) &&
                ( pSession->rtpConfig.audioCodecRtxPayload != pSession->rtpConfig.audioCodecPayload ) )
            {
                bufferAfterEncrypt = 0;
            }
        }

        if( xSemaphoreTake( pSrtpSender->senderMutex, portMAX_DELAY ) == pdTRUE )
        {
            isLocked = 1;
        }
        else
        {
            LogError( ( "Fail to take sender mutex" ) );
            ret = PEER_CONNECTION_RESULT_FAIL_TAKE_SENDER_MUTEX;
        }
    }

    while( ret == PEER_CONNECTION_RESULT_OK )
    {
        /* Get buffer from sender for later use.
         * PeerConnectionRollingBuffer_GetRtpSequenceBuffer() returns the buffer with its size.
         * If the bufferAfterEncrypt = 0, we store only RTP payload to the buffer.
         * If the bufferAfterEncrypt = 1, we store the encrypted SRTP packet to the buffer. */
        ret = PeerConnectionRollingBuffer_GetRtpSequenceBuffer( &pSrtpSender->txRollingBuffer,
                                                                *pRtpSeq,
                                                                &pRollingBufferPacket );
        if( ret != PEER_CONNECTION_RESULT_OK )
        {
            LogWarn( ( "Fail to get RTP buffer for seq: %u", *pRtpSeq ) );
            break;
        }

        /* Get each NALU payload then serialize SRTP packet. */
        if( bufferAfterEncrypt == 0 )
        {
            packetH264.pPacketData = pRollingBufferPacket->pPacketBuffer;
            packetH264.packetDataLength = pRollingBufferPacket->packetBufferLength;

            /* Using local buffer for SRTP packet, use the entire packet length. */
            pSrtpPacket = rtpBuffer;
            srtpPacketLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;
        }
        else
        {
            /* Using local buffer for RTP payload only, set RTP payload length. */
            packetH264.pPacketData = rtpBuffer;
            packetH264.packetDataLength = PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH;

            pSrtpPacket = pRollingBufferPacket->pPacketBuffer;
            srtpPacketLength = pRollingBufferPacket->packetBufferLength;
        }

        resultH264 = H264Packetizer_GetPacket( &h264PacketizerContext,
                                               &packetH264 );
        if( resultH264 == H264_RESULT_NO_MORE_PACKETS )
        {
            PeerConnectionRollingBuffer_DiscardRtpSequenceBuffer( &pSrtpSender->txRollingBuffer,
                                                                  pRollingBufferPacket );
            /* Eraly break because no packet available. */
            break;
        }
        else if( resultH264 == H264_RESULT_OK )
        {
            ret = ConstructSrtpPacket( pSession,
                                       pTransceiver,
                                       packetH264.pPacketData,
                                       packetH264.packetDataLength,
                                       h264PacketizerContext.naluCount == 0 ? 1U : 0U,
                                       PEER_CONNECTION_SRTP_CONVERT_TIME_US_TO_RTP_TIMESTAMP( PEER_CONNECTION_SRTP_VIDEO_CLOCKRATE, pFrame->presentationUs ),
                                       pSrtpPacket,
                                       &srtpPacketLength,
                                       &pRollingBufferPacket->rtpPacket,
                                       payloadType,
                                       *pRtpSeq,
                                       *pSsrc );
        }
        else
        {
            LogError( ( "Fail to get H264 packet, result: %d", resultH264 ) );
            ret = PEER_CONNECTION_RESULT_FAIL_PACKETIZER_GET_PACKET;
        }

        if( ret == PEER_CONNECTION_RESULT_OK )
        {
            /* Udpate the packet into rolling buffer. */
            ret = PeerConnectionRollingBuffer_SetPacket( &pSrtpSender->txRollingBuffer,
                                                         ( *pRtpSeq )++,
                                                         pRollingBufferPacket );
        }

        /* Write the constructed RTP packets through network. */
        if( ret == PEER_CONNECTION_RESULT_OK )
        {
            resultIceController = IceController_SendToRemotePeer( &pSession->iceControllerContext,
                                                                  pSrtpPacket,
                                                                  srtpPacketLength );
            if( resultIceController != ICE_CONTROLLER_RESULT_OK )
            {
                LogWarn( ( "Fail to send RTP packet, ret: %d", resultIceController ) );
                ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_RTP_PACKET;
            }
        }

        if( ( ret != PEER_CONNECTION_RESULT_OK ) && ( pRollingBufferPacket != NULL ) )
        {
            /* If any failure, release the allocated RTP buffer. */
            PeerConnectionRollingBuffer_DiscardRtpSequenceBuffer( &pSrtpSender->txRollingBuffer,
                                                                  pRollingBufferPacket );
        }
    }

    if( isLocked )
    {
        xSemaphoreGive( pSrtpSender->senderMutex );
    }

    return ret;
}

PeerConnectionResult_t PeerConnectionSrtp_HandleSrtpPacket( PeerConnectionSession_t * pSession,
                                                            uint8_t * pBuffer,
                                                            size_t bufferLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    srtp_err_status_t errorStatus;
    static uint8_t rtpBuffer[ PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH ];
    size_t rtpBufferLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;

    if( ( pSession == NULL ) || ( pBuffer == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pBuffer: %p", pSession, pBuffer ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        errorStatus = srtp_unprotect( pSession->srtpReceiveSession,
                                      pBuffer,
                                      bufferLength,
                                      rtpBuffer,
                                      &rtpBufferLength );
        if( errorStatus != srtp_err_status_ok )
        {
            LogError( ( "Fail to decrypt Rx SRTP packet, errorStatus: %d", errorStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_DECRYPT_SRTP_RTP_PACKET;
        }
        else
        {
            LogVerbose( ( "Decrypt SRTP packet successfully, decrypted length: %u", rtpBufferLength ) );
        }
    }

    return ret;
}

PeerConnectionResult_t PeerConnectionSrtp_HandleSrtcpPacket( PeerConnectionSession_t * pSession,
                                                             uint8_t * pBuffer,
                                                             size_t bufferLength )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    srtp_err_status_t errorStatus;
    static uint8_t rtcpBuffer[ PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH ];
    size_t rtcpBufferLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;
    RtcpResult_t resultRtcp;
    RtcpPacket_t rtcpPacket;

    if( ( pSession == NULL ) || ( pBuffer == NULL ) )
    {
        LogError( ( "Invalid input, pSession: %p, pBuffer: %p", pSession, pBuffer ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        errorStatus = srtp_unprotect_rtcp( pSession->srtpReceiveSession,
                                           pBuffer,
                                           bufferLength,
                                           rtcpBuffer,
                                           &rtcpBufferLength );
        if( errorStatus != srtp_err_status_ok )
        {
            LogError( ( "Fail to decrypt Rx SRTP packet, errorStatus: %d", errorStatus ) );
            ret = PEER_CONNECTION_RESULT_FAIL_DECRYPT_SRTP_RTP_PACKET;
        }
        else
        {
            LogVerbose( ( "Decrypt SRTCP packet successfully, decrypted length: %u", rtpBufferLength ) );
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        resultRtcp = Rtcp_DeserializePacket( &pSession->pCtx->rtcpContext,
                                             rtcpBuffer,
                                             rtcpBufferLength,
                                             &rtcpPacket );
        if( resultRtcp != RTCP_RESULT_OK )
        {
            LogError( ( "Fail to deserialize RTCP packet, result: %d", resultRtcp ) );
            ret = PEER_CONNECTION_RESULT_FAIL_RTCP_DESERIALIZE;
        }
    }

    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        switch( rtcpPacket.header.packetType )
        {
            case RTCP_PACKET_FIR:
                // CHK_STATUS(onRtcpFIRPacket(&rtcpPacket, pKvsPeerConnection));
                break;
            case RTCP_PACKET_TRANSPORT_FEEDBACK_NACK:
                ret = OnRtcpNackEvent( pSession, &rtcpPacket );
                break;
            case RTCP_PACKET_TRANSPORT_FEEDBACK_TWCC:
                // if (rtcpPacket.header.receptionReportCount == RTCP_FEEDBACK_MESSAGE_TYPE_NACK) {
                //     CHK_STATUS(resendPacketOnNack(&rtcpPacket, pKvsPeerConnection));
                // } else if (rtcpPacket.header.receptionReportCount == RTCP_FEEDBACK_MESSAGE_TYPE_APPLICATION_LAYER_FEEDBACK) {
                //     CHK_STATUS(onRtcpTwccPacket(&rtcpPacket, pKvsPeerConnection));
                // } else {
                //     DLOGW("unhandled RTCP_PACKET_TYPE_GENERIC_RTP_FEEDBACK %d", rtcpPacket.header.receptionReportCount);
                // }
                break;
            case RTCP_PACKET_PAYLOAD_FEEDBACK_PLI:
            case RTCP_PACKET_PAYLOAD_FEEDBACK_SLI:
            case RTCP_PACKET_PAYLOAD_FEEDBACK_REMB:
                // if (rtcpPacket.header.receptionReportCount == RTCP_FEEDBACK_MESSAGE_TYPE_APPLICATION_LAYER_FEEDBACK &&
                //     isRembPacket(rtcpPacket.payload, rtcpPacket.payloadLength) == STATUS_SUCCESS) {
                //     CHK_STATUS(onRtcpRembPacket(&rtcpPacket, pKvsPeerConnection));
                // } else if (rtcpPacket.header.receptionReportCount == RTCP_PSFB_PLI) {
                //     CHK_STATUS(onRtcpPLIPacket(&rtcpPacket, pKvsPeerConnection));
                // } else if (rtcpPacket.header.receptionReportCount == RTCP_PSFB_SLI) {
                //     CHK_STATUS(onRtcpSLIPacket(&rtcpPacket, pKvsPeerConnection));
                // } else {
                //     DLOGW("unhandled packet type RTCP_PACKET_TYPE_PAYLOAD_SPECIFIC_FEEDBACK %d", rtcpPacket.header.receptionReportCount);
                // }
                break;
            case RTCP_PACKET_SENDER_REPORT:
                // CHK_STATUS(onRtcpSenderReport(&rtcpPacket, pKvsPeerConnection));
                break;
            case RTCP_PACKET_RECEIVER_REPORT:
                // CHK_STATUS(onRtcpReceiverReport(&rtcpPacket, pKvsPeerConnection));
                break;
            default:
                LogWarn( ( "unhandled packet type %d", rtcpPacket.header.packetType ) );
                break;
        }
    }

    return ret;
}
