#ifndef PEER_CONNECTION_H
#define PEER_CONNECTION_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include "peer_connection_data_types.h"
#include "signaling_controller_data_types.h"

PeerConnectionResult_t PeerConnection_Init( PeerConnectionContext_t * pCtx,
                                            SignalingControllerContext_t * pSignalingControllerContext );
PeerConnectionResult_t PeerConnection_Destroy( PeerConnectionContext_t * pCtx );
PeerConnectionResult_t PeerConnection_AddTransceiver( PeerConnectionContext_t * pCtx,
                                                      Transceiver_t * pTransceiver );
PeerConnectionResult_t PeerConnection_MatchTransceiverBySsrc( PeerConnectionContext_t * pCtx,
                                                              uint32_t ssrc,
                                                              const Transceiver_t ** ppTransceiver );
PeerConnectionResult_t PeerConnection_SetLocalDescription( PeerConnectionContext_t * pCtx );
PeerConnectionResult_t PeerConnection_SetRemoteDescription( PeerConnectionContext_t * pCtx,
                                                            const PeerConnectionRemoteInfo_t * pRemoteInfo );
PeerConnectionResult_t PeerConnection_AddRemoteCandidate( PeerConnectionContext_t * pCtx,
                                                          const char * pRemoteClientId,
                                                          size_t remoteClientIdLength,
                                                          const char * pDecodeMessage,
                                                          size_t decodeMessageLength );
PeerConnectionResult_t PeerConnection_GetTransceivers( PeerConnectionContext_t * pCtx,
                                                       const Transceiver_t * ppTransceivers[],
                                                       size_t * pTransceiversCount );
PeerConnectionResult_t PeerConnection_GetLocalUserInfo( PeerConnectionContext_t * pCtx,
                                                        PeerConnectionUserInfo_t * pLocalUserInfo );
PeerConnectionResult_t PeerConnection_CreateSession( PeerConnectionContext_t * pCtx,
                                                     const char * pRemoteClientId,
                                                     size_t remoteClientIdLength,
                                                     const char ** ppLocalFingerprint,
                                                     size_t * pLocalFingerprint );
PeerConnectionResult_t PeerConnection_CloseSession( PeerConnectionContext_t * pCtx,
                                                    const char * pRemoteClientId,
                                                    size_t remoteClientIdLength );
PeerConnectionResult_t PeerConnection_WriteFrame( PeerConnectionContext_t * pCtx,
                                                  Transceiver_t * pTransceiver,
                                                  const PeerConnectionFrame_t * pFrame );

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_H */
