#ifndef PEER_CONNECTION_ROLLING_BUFFER_H
#define PEER_CONNECTION_ROLLING_BUFFER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

#include "peer_connection_data_types.h"

#define PEER_CONNECTION_ROLLING_BUFFER_DURATION_IN_SECONDS ( 3 )

PeerConnectionResult_t PeerConnectionRollingBuffer_Create( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                           uint32_t rollingbufferBitRate,  // bps
                                                           uint32_t rollingbufferDurationSec,  // duration in seconds
                                                           size_t maxSizePerPacket );

void PeerConnectionRollingBuffer_Free( PeerConnectionRollingBuffer_t * pRollingBuffer );

PeerConnectionResult_t PeerConnectionRollingBuffer_GetRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                                         uint16_t rtpSeq,
                                                                         uint8_t ** ppBuffer,
                                                                         size_t * pBufferLength );

void PeerConnectionRollingBuffer_DiscardRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                           uint8_t * pBuffer );

PeerConnectionResult_t PeerConnectionRollingBuffer_SearchRtpSequenceBuffer( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                                            uint16_t rtpSeq,
                                                                            uint8_t ** ppBuffer,
                                                                            size_t * pBufferLength );

PeerConnectionResult_t PeerConnectionRollingBuffer_SetPacket( PeerConnectionRollingBuffer_t * pRollingBuffer,
                                                              uint16_t rtpSeq,
                                                              uint8_t * pBuffer,
                                                              size_t bufferLength );

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_ROLLING_BUFFER_H */
