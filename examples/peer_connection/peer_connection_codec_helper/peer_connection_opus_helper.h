#ifndef OPUS_CODEC_H
#define OPUS_CODEC_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

#include "peer_connection_data_types.h"

PeerConnectionResult_t GetOpusPacketProperty( PeerConnectionJitterBufferPacket_t * pPacket,
                                              uint8_t * pIsStartPacket );

PeerConnectionResult_t FillFrameOpus( PeerConnectionJitterBuffer_t * pJitterBuffer,
                                      uint16_t rtpSeqStart,
                                      uint16_t rtpSeqEnd,
                                      uint8_t * pOutBuffer,
                                      size_t * pOutBufferLength,
                                      uint32_t * pRtpTimestamp );

PeerConnectionResult_t PeerConnectionSrtp_WriteOpusFrame( PeerConnectionSession_t * pSession,
                                                          Transceiver_t * pTransceiver,
                                                          const PeerConnectionFrame_t * pFrame );

#ifdef __cplusplus
}
#endif

#endif /* OPUS_CODEC_H */
