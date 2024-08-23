#ifndef PEER_CONNECTION_SRTP_H
#define PEER_CONNECTION_SRTP_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include "peer_connection_data_types.h"

PeerConnectionResult_t PeerConnectionSrtp_Init( PeerConnectionSession_t * pSession );
PeerConnectionResult_t PeerConnectionSrtp_WriteH264Frame( PeerConnectionContext_t * pCtx,
                                                          Transceiver_t * pTransceiver,
                                                          const PeerConnectionFrame_t * pFrame );
// PeerConnectionResult_t PeerConnectionSrtp_EncryptRtpPacket( PeerConnectionSession_t * pSession );
// PeerConnectionResult_t PeerConnectionSrtp_EncryptRtcpPacket( PeerConnectionSession_t * pSession );
// PeerConnectionResult_t PeerConnectionSrtp_DecryptRtpPacket( PeerConnectionSession_t * pSession );
// PeerConnectionResult_t PeerConnectionSrtp_DecryptRtcpPacket( PeerConnectionSession_t * pSession );

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_SRTP_H */
