#include <stdlib.h>
#include "logging.h"
#include "peer_connection.h"

/* API includes. */
#include "rtp_api.h"
#include "h264_packetizer.h"
#include "ice_controller.h"

#define PEER_CONNECTION_SRTP_H264_MAX_NALUS_IN_A_FRAME        64
#define PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH      1200
#define PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH      1400

#define PEER_CONNECTION_SRTP_VIDEO_CLOCKRATE ( uint32_t ) 90000
#define PEER_CONNECTION_SRTP_OPUS_CLOCKRATE  ( uint32_t ) 48000
#define PEER_CONNECTION_SRTP_PCM_CLOCKRATE   ( uint32_t ) 8000

#define PEER_CONNECTION_SRTP_US_IN_A_SECOND ( 1000000 )
#define PEER_CONNECTION_SRTP_CONVERT_TIME_US_TO_RTP_TIMESTAMP( clockRate, presentationUs ) ( uint32_t )( ( ( ( presentationUs ) * ( clockRate ) ) / PEER_CONNECTION_SRTP_US_IN_A_SECOND ) & 0xFFFFFFFF )

static PeerConnectionResult_t ConstructRtpAndSendSessions( PeerConnectionContext_t * pCtx,
                                                           Transceiver_t * pTransceiver,
                                                           uint8_t * pBuffer,
                                                           size_t bufferLength,
                                                           uint8_t isLastPacket,
                                                           uint32_t rtpTimestamp )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    RtpResult_t resultRtp;
    RtpPacket_t packetRtp;
    int i;
    PeerConnectionSession_t * pSession = NULL;
    uint8_t rtpBuffer[ PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH ];
    size_t rtpBufferLength;
    size_t srtpBufferLength;
    IceControllerResult_t resultIceController;
    srtp_err_status_t errorStatus;

    if( ( pCtx == NULL ) ||
        ( pBuffer == NULL ) ||
        ( pTransceiver == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pBuffer: %p, pTransceiver: %p", pCtx, pBuffer, pTransceiver ) );
        ret = PEER_CONNECTION_RESULT_BAD_PARAMETER;
    }

    /* Contruct RTP packet for each payload buffer. */
    if( ret == PEER_CONNECTION_RESULT_OK )
    {
        // LogDebug( ( "Serializing RTP packet with size: %u, rtpTimestamp: %lu", bufferLength, rtpTimestamp ) );
        for( i = 0; i < AWS_MAX_VIEWER_NUM; i++ )
        {
            if( pCtx->peerConnectionSessions[i].state < PEER_CONNECTION_SESSION_STATE_CONNECTION_READY )
            {
                continue;
            }

            pSession = &pCtx->peerConnectionSessions[i];
            memset( &packetRtp, 0, sizeof( packetRtp ) );
            if( isLastPacket )
            {
                /* This is the last packet, set the marker. */
                packetRtp.header.flags |= RTP_HEADER_FLAG_MARKER;
            }

            if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
            {
                packetRtp.header.payloadType = pSession->rtpConfig.videoCodecPayload;
                packetRtp.header.sequenceNumber = pSession->rtpConfig.videoSequenceNumber++;
                packetRtp.header.ssrc = pTransceiver->ssrc;
            }
            else
            {
                packetRtp.header.payloadType = pSession->rtpConfig.audioCodecPayload;
                packetRtp.header.sequenceNumber = pSession->rtpConfig.audioSequenceNumber++;
            }
            packetRtp.header.csrcCount = 0;
            packetRtp.header.pCsrc = NULL;
            packetRtp.header.timestamp = rtpTimestamp;

#define TWCC_PAYLOAD( extId, sequenceNum ) ( ( ( ( extId ) & 0xfu ) << 28u ) | ( 1u << 24u ) | ( ( uint32_t ) ( sequenceNum ) << 8u ) )
            static uint16_t twsn = 0;
            uint32_t extensionPayload;
            packetRtp.header.flags |= RTP_HEADER_FLAG_EXTENSION;
            packetRtp.header.extension.extensionProfile = 0xBEDE;
            packetRtp.header.extension.extensionPayloadLength = 1;
            extensionPayload = TWCC_PAYLOAD( 4, twsn );
            packetRtp.header.extension.pExtensionPayload = &extensionPayload;
            twsn++;

            packetRtp.payloadLength = bufferLength;
            packetRtp.pPayload = pBuffer;
            rtpBufferLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;
            // LogDebug( ( "Serializing RTP packet, packetRtp.header.flags: 0x%lx, packetRtp.header.csrcCount: %u, packetRtp.header.payloadType: %u, packetRtp.header.sequenceNumber: %u, packetRtp.header.timestamp: %lu, packetRtp.header.ssrc: %lu",
            //             packetRtp.header.flags,
            //             packetRtp.header.csrcCount,
            //             packetRtp.header.payloadType,
            //             packetRtp.header.sequenceNumber,
            //             packetRtp.header.timestamp,
            //             packetRtp.header.ssrc ) );
            // LogDebug( ( "Serializing RTP packet, packetRtp.header.extension.extensionProfile: %u, packetRtp.header.extension.extensionPayloadLength: %u, packetRtp.header.extension.pExtensionPayload: 0x%lx, packetRtp.payloadLength: %u",
            //             packetRtp.header.extension.extensionProfile,
            //             packetRtp.header.extension.extensionPayloadLength,
            //             *packetRtp.header.extension.pExtensionPayload,
            //             packetRtp.payloadLength ) );

            resultRtp = Rtp_Serialize( &pCtx->rtpContext,
                                       &packetRtp,
                                       rtpBuffer,
                                       &rtpBufferLength );
            if( resultRtp != RTP_RESULT_OK )
            {
                LogError( ( "Fail to serialize RTP packet, result: %d", resultRtp ) );
                ret = PEER_CONNECTION_RESULT_FAIL_RTP_SERIALIZE;
                break;
            }

            /* Encrypt it by SRTP. */
            srtpBufferLength = PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH;
            errorStatus = srtp_protect( pSession->srtpTransmitSession, rtpBuffer, rtpBufferLength, rtpBuffer, &srtpBufferLength, 0 );
            if( errorStatus != srtp_err_status_ok )
            {
                LogError( ( "Fail to encrypt Tx SRTP packet, errorStatus: %d", errorStatus ) );
                ret = PEER_CONNECTION_RESULT_FAIL_ENCRYPT_SRTP_RTP_PACKET;
                break;
            }

            // LogDebug( ( "After SRTP encryption, the packet size: %u, RTP seq: %u", srtpBufferLength, packetRtp.header.sequenceNumber ) );
            /* Write the constructed RTP packets through network. */
            resultIceController = IceController_SendToRemotePeer( &pSession->iceControllerContext,
                                                                  rtpBuffer,
                                                                  srtpBufferLength );
            if( resultIceController != ICE_CONTROLLER_RESULT_OK )
            {
                LogWarn( ( "Fail to send RTP packet, ret: %d", resultIceController ) );
                ret = PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_RTP_PACKET;
                break;
            }

            /* Store the frame into rolling buffer. */
            if( ret == PEER_CONNECTION_RESULT_OK )
            {
                /* TODO */
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

    return ret;
}

PeerConnectionResult_t PeerConnectionSrtp_WriteH264Frame( PeerConnectionContext_t * pCtx,
                                                          Transceiver_t * pTransceiver,
                                                          const PeerConnectionFrame_t * pFrame )
{
    PeerConnectionResult_t ret = PEER_CONNECTION_RESULT_OK;
    H264PacketizerContext_t h264PacketizerContext;
    H264Result_t resultH264;
    H264Packet_t packetH264;
    uint8_t buffer[ PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH ];
    Nalu_t nalusArray[ PEER_CONNECTION_SRTP_H264_MAX_NALUS_IN_A_FRAME ];
    Frame_t h264Frame;

    if( ( pCtx == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pFrame == NULL ) )
    {
        LogError( ( "Invalid input, pCtx: %p, pTransceiver: %p, pFrame: %p",
                    pCtx, pTransceiver, pFrame ) );
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

    while( ret == PEER_CONNECTION_RESULT_OK )
    {
        packetH264.pPacketData = buffer;
        packetH264.packetDataLength = PEER_CONNECTION_SRTP_RTP_PAYLOAD_MAX_LENGTH;
        resultH264 = H264Packetizer_GetPacket( &h264PacketizerContext,
                                               &packetH264 );
        if( resultH264 == H264_RESULT_NO_MORE_PACKETS )
        {
            break;
        }
        else if( resultH264 == H264_RESULT_OK )
        {
            ret = ConstructRtpAndSendSessions( pCtx,
                                               pTransceiver,
                                               buffer,
                                               packetH264.packetDataLength,
                                               h264PacketizerContext.naluCount == 0 ? 1U : 0U,
                                               PEER_CONNECTION_SRTP_CONVERT_TIME_US_TO_RTP_TIMESTAMP( PEER_CONNECTION_SRTP_VIDEO_CLOCKRATE, pFrame->presentationUs ) );
        }
        else
        {
            LogError( ( "Fail to get H264 packet, result: %d", resultH264 ) );
            ret = PEER_CONNECTION_RESULT_FAIL_PACKETIZER_GET_PACKET;
        }
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
