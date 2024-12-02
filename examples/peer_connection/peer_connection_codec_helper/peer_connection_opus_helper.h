#ifndef PEER_CONNECTION_OPUS_HELPER_H
#define PEER_CONNECTION_OPUS_HELPER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

#include "peer_connection_data_types.h"

PeerConnectionResult_t PeerConnectionOpusHelper_GetOpusPacketProperty( PeerConnectionJitterBufferPacket_t * pPacket,
                                                                       uint8_t * pIsStartPacket );

PeerConnectionResult_t PeerConnectionOpusHelper_FillFrameOpus( PeerConnectionJitterBuffer_t * pJitterBuffer,
                                                               uint16_t rtpSeqStart,
                                                               uint16_t rtpSeqEnd,
                                                               uint8_t * pOutBuffer,
                                                               size_t * pOutBufferLength,
                                                               uint32_t * pRtpTimestamp );

PeerConnectionResult_t PeerConnectionOpusHelper_WriteOpusFrame( PeerConnectionSession_t * pSession,
                                                                Transceiver_t * pTransceiver,
                                                                const PeerConnectionFrame_t * pFrame );

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_OPUS_HELPER_H */
