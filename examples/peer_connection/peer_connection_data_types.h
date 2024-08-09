#ifndef PEER_CONNECTION_DATA_TYPES_H
#define PEER_CONNECTION_DATA_TYPES_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>

#include "ice_controller.h"
#include "transceiver_data_types.h"

#define PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ( 2 )

typedef enum PeerConnectionResult
{
    PEER_CONNECTION_RESULT_OK = 0,
    PEER_CONNECTION_RESULT_BAD_PARAMETER,
    PEER_CONNECTION_RESULT_NO_FREE_TRANSCEIVER,
    PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_CONTROLLER,
    PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_SOCK_LISTENER,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_INIT,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESTROY,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SET_REMOTE_DESCRIPTION,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESERIALIZE_CANDIDATE,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_REMOTE_CANDIDATE,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_CREATE_DTLS_SESSION,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_GET_LOCAL_FINGERPRINT,
} PeerConnectionResult_t;

typedef struct PeerConnectionRemoteInfo
{
    const char * pRemoteClientId; /* From SignalingControllerReceiveEvent_t */
    size_t remoteClientIdLength;
    const char * pRemoteUserName; /* From ice-ufrag in SDP attributes */
    size_t remoteUserNameLength;
    const char * pRemotePassword; /* From ice-pwd in SDP attributes */
    size_t remotePasswordLength;
} PeerConnectionRemoteInfo_t;

typedef struct PeerConnectionUserInfo
{
    const char * pCname;
    size_t cnameLength;
    const char * pUserName; /* For ice-ufrag in SDP attributes */
    size_t userNameLength;
    const char * pPassword; /* For ice-pwd in SDP attributes */
    size_t passwordLength;
} PeerConnectionUserInfo_t;

typedef struct PeerConnectionContext
{
    Transceiver_t transceivers[ PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ];
    uint32_t transceiverCount;
    IceControllerContext_t iceControllerContext;
} PeerConnectionContext_t;

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_DATA_TYPES_H */
