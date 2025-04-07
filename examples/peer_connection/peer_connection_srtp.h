#ifndef PEER_CONNECTION_SRTP_H
#define PEER_CONNECTION_SRTP_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include "peer_connection_data_types.h"

#define PEER_CONNECTION_SRTP_RTP_PACKET_MAX_LENGTH      ( 1400 )
#define PEER_CONNECTION_SRTP_VIDEO_CLOCKRATE ( uint32_t ) 90000
#define PEER_CONNECTION_SRTP_OPUS_CLOCKRATE  ( uint32_t ) 48000
#define PEER_CONNECTION_SRTP_PCM_CLOCKRATE   ( uint32_t ) 8000

#define PEER_CONNECTION_SRTP_US_IN_A_SECOND ( 1000000 )
#define PEER_CONNECTION_SRTP_CONVERT_TIME_US_TO_RTP_TIMESTAMP( clockRate, presentationUs ) ( uint32_t )( ( ( ( presentationUs ) * ( clockRate ) ) / PEER_CONNECTION_SRTP_US_IN_A_SECOND ) & 0xFFFFFFFF )
#define PEER_CONNECTION_SRTP_CONVERT_RTP_TIMESTAMP_TO_TIME_US( clockRate, rtpTimestamp ) ( ( uint64_t )( rtpTimestamp ) * PEER_CONNECTION_SRTP_US_IN_A_SECOND / ( clockRate ) )

PeerConnectionResult_t PeerConnectionSrtp_Init( PeerConnectionSession_t * pSession );
PeerConnectionResult_t PeerConnectionSrtp_DeInit( PeerConnectionSession_t * pSession );
PeerConnectionResult_t PeerConnectionSrtp_HandleSrtpPacket( PeerConnectionSession_t * pSession,
                                                            uint8_t * pBuffer,
                                                            size_t bufferLength );
PeerConnectionResult_t PeerConnectionSrtp_ConstructSrtpPacket( PeerConnectionSession_t * pSession,
                                                               RtpPacket_t * pPacketRtp,
                                                               uint8_t * pOutputSrtpPacket,
                                                               size_t * pOutputSrtpPacketLength );

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_SRTP_H */
