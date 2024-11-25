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

PeerConnectionResult_t PeerConnectionSrtp_WriteOpusFrame( PeerConnectionSession_t * pSession,
                                                          Transceiver_t * pTransceiver,
                                                          const PeerConnectionFrame_t * pFrame );

#ifdef __cplusplus
}
#endif

#endif /* OPUS_CODEC_H */
