#ifndef ICE_CONTROLLER_DATA_TYPES_H
#define ICE_CONTROLLER_DATA_TYPES_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>
#include "demo_config.h"
#include "ice_data_types.h"
#include "signaling_controller_data_types.h"
#include "timer_controller.h"
#include "lwip/sockets.h"
#include "transport_dtls_mbedtls.h"
#include "transport_interface.h"

/* FreeRTOS includes. */
#include "semphr.h"

// #define KVS_IP_ADDRESS_STRING_BUFFER_LEN ( 46 )
#define ICE_CONTROLLER_IP_ADDR_STRING_BUFFER_LENGTH ( 39 )
#define ICE_CONTROLLER_USER_NAME_LENGTH ( 4 )
#define ICE_CONTROLLER_PASSWORD_LENGTH ( 24 )
#define ICE_CONTROLLER_CNAME_LENGTH ( 16 )
#define ICE_CONTROLLER_STUN_MESSAGE_BUFFER_SIZE ( 1024 )

/**
 * Maximum allowed ICE URI length
 */
#define ICE_CONTROLLER_ICE_SERVER_URL_MAX_LENGTH ( 256 )

/**
 * Maximum allowed ICE configuration user name length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_GetIceServerConfig.html#API_AWSAcuitySignalingService_GetIceServerConfig_RequestSyntax
 */
#define ICE_CONTROLLER_ICE_SERVER_USERNAME_MAX_LENGTH ( 256 )

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define ICE_CONTROLLER_ICE_SERVER_PASSWORD_MAX_LENGTH ( 256 )

#define ICE_CONTROLLER_MAX_CANDIDATE_PAIR_COUNT       ( 1024 )
#define ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT      ( 100 )
#define ICE_CONTROLLER_MAX_REMOTE_CANDIDATE_COUNT     ( 100 )

#define ICE_CONTROLLER_CONNECTIVITY_TIMER_INTERVAL_MS ( 5000 )

#define AWS_DEFAULT_STUN_SERVER_URL_POSTFIX "amazonaws.com"
#define AWS_DEFAULT_STUN_SERVER_URL_POSTFIX_CN "amazonaws.com.cn"
#define AWS_DEFAULT_STUN_SERVER_URL "stun.kinesisvideo.%s.%s"

/* This is the URI format for STUN server as reference here. Note that we're using port 443 by default. */
#define AWS_DEFAULT_STUN_SERVER_URI "stun:stun.kinesisvideo.%s.%s:443"

typedef enum IceControllerResult
{
    ICE_CONTROLLER_RESULT_OK = 0,
    ICE_CONTROLLER_RESULT_BAD_PARAMETER,
    ICE_CONTROLLER_RESULT_IPV6_NOT_SUPPORT,
    ICE_CONTROLLER_RESULT_IP_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_RFDS_TOO_SMALL,
    ICE_CONTROLLER_RESULT_CANDIDATE_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_CANDIDATE_STRING_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_STUN_URL_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_USERNAME_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_PASSWORD_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_URL_BUFFER_TOO_SMALL,
    ICE_CONTROLLER_RESULT_CANDIDATE_SEND_FAIL,
    ICE_CONTROLLER_RESULT_INVALID_IP_ADDR,
    ICE_CONTROLLER_RESULT_INVALID_JSON,
    ICE_CONTROLLER_RESULT_INVALID_REMOTE_CLIENT_ID,
    ICE_CONTROLLER_RESULT_INVALID_REMOTE_USERNAME,
    ICE_CONTROLLER_RESULT_INVALID_RX_PACKET_FAMILY,
    ICE_CONTROLLER_RESULT_INVALID_ICE_SERVER,
    ICE_CONTROLLER_RESULT_INVALID_ICE_SERVER_PORT,
    ICE_CONTROLLER_RESULT_INVALID_ICE_SERVER_PROTOCOL,
    ICE_CONTROLLER_RESULT_UNKNOWN_REMOTE_CLIENT_ID,
    ICE_CONTROLLER_RESULT_FAIL_CREATE_ICE_AGENT,
    ICE_CONTROLLER_RESULT_FAIL_SOCKET_CREATE,
    ICE_CONTROLLER_RESULT_FAIL_SOCKET_BIND,
    ICE_CONTROLLER_RESULT_FAIL_SOCKET_GETSOCKNAME,
    ICE_CONTROLLER_RESULT_FAIL_SOCKET_SENDTO,
    ICE_CONTROLLER_RESULT_FAIL_ADD_HOST_CANDIDATE,
    ICE_CONTROLLER_RESULT_FAIL_ADD_REMOTE_CANDIDATE,
    ICE_CONTROLLER_RESULT_FAIL_MQ_INIT,
    ICE_CONTROLLER_RESULT_FAIL_MQ_SEND,
    ICE_CONTROLLER_RESULT_FAIL_MQ_ATTACH_POLL,
    ICE_CONTROLLER_RESULT_FAIL_TIMER_INIT,
    ICE_CONTROLLER_RESULT_FAIL_POLLING,
    ICE_CONTROLLER_RESULT_FAIL_RECVFROM,
    ICE_CONTROLLER_RESULT_FAIL_QUERY_ICE_SERVER_CONFIGS,
    ICE_CONTROLLER_RESULT_FAIL_SNPRINTF,
    ICE_CONTROLLER_RESULT_FAIL_DNS_QUERY,
    ICE_CONTROLLER_RESULT_FAIL_SET_CONNECTIVITY_CHECK_TIMER,
    ICE_CONTROLLER_RESULT_FAIL_QUERY_CANDIDATE_PAIR_COUNT,
    ICE_CONTROLLER_RESULT_FAIL_MUTEX_CREATE,
    ICE_CONTROLLER_RESULT_FAIL_MUTEX_TAKE,
    ICE_CONTROLLER_RESULT_FAIL_CREATE_CERT_AND_KEY,
    ICE_CONTROLLER_RESULT_FAIL_CREATE_CERT_FINGERPRINT,
    ICE_CONTROLLER_RESULT_FAIL_WRITE_KEY_PEM,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_NOT_FOUND,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_INVALID_PRIORITY,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_INVALID_PROTOCOL,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_INVALID_PORT,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_INVALID_TYPE_ID,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_INVALID_TYPE,
    ICE_CONTROLLER_RESULT_JSON_CANDIDATE_LACK_OF_ELEMENT,
    ICE_CONTROLLER_RESULT_EXCEED_REMOTE_PEER,
    ICE_CONTROLLER_RESULT_NO_MORE_RX_PACKET,
    ICE_CONTROLLER_RESULT_FOUND_CONNECTION,
} IceControllerResult_t;

/* https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate/candidate
 * https://tools.ietf.org/html/rfc5245#section-15.1 */
typedef enum IceControllerCandidateDeserializerState
{
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_FOUNDATION = 0,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_COMPONENT,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_PROTOCOL,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_PRIORITY,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_IP,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_PORT,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_TYPE_ID,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_TYPE_VAL,
    ICE_CONTROLLER_CANDIDATE_DESERIALIZER_STATE_MAX,
} IceControllerCandidateDeserializerState_t;

typedef enum IceControllerIceServerType
{
    ICE_CONTROLLER_ICE_SERVER_TYPE_NONE = 0,
    ICE_CONTROLLER_ICE_SERVER_TYPE_STUN,
    ICE_CONTROLLER_ICE_SERVER_TYPE_TURN,
} IceControllerIceServerType_t;

typedef struct IceControllerMetrics
{
    struct timeval gatheringCandidateStartTime;
    struct timeval gatheringCandidateEndTime;
    struct timeval allSrflxCandidateReadyTime;
    struct timeval firstConnectivityRequestTime;
    struct timeval sentNominationResponseTime;
    uint32_t pendingSrflxCandidateNum;
    uint32_t isFirstConnectivityRequest;
} IceControllerMetrics_t;

typedef struct IceControllerCandidate
{
    char remoteClientId[ SIGNALING_CONTROLLER_REMOTE_ID_MAX_LENGTH ];
    size_t remoteClientIdLength;
    IceSocketProtocol_t protocol;
    uint32_t priority;
    IceEndpoint_t iceEndpoint;
    IceCandidateType_t candidateType;
} IceControllerCandidate_t;

typedef struct IceControllerSignalingRemoteInfo IceControllerRemoteInfo_t;

typedef struct IceControllerSocketContext
{
    IceCandidateType_t candidateType; /* server socket of host/srflx/relay candidate or client socket connecting with remote. */
    IceCandidate_t * pLocalCandidate;
    int socketFd;
    Socket_t udpSocket;
    IceControllerRemoteInfo_t * pRemoteInfo;
} IceControllerSocketContext_t;

typedef struct DtlsTestCredentials
{
    /* user-agent */
    char *pUserAgent;
    size_t userAgentLength;

    /* Region */
    char * pRegion;
    size_t regionLength;

    /* AKSK */
    char * pAccessKeyId;
    size_t accessKeyIdLength;
    char * pSecretAccessKey;
    size_t secretAccessKeyLength;

    /* CA Cert Path */
    char * pCaCertPath;
    char * pCaCertPem;

    /* Or CA PEM */
    const uint8_t * pRootCa;
    size_t rootCaSize;

} DtlsTestCredentials_t;

typedef struct DtlsTestContext {
    DtlsTestCredentials_t credentials;

    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t xTransportInterface;
    /* The network context for the transport layer interface. */

    DtlsNetworkContext_t xNetworkContext;
    DtlsTransportParams_t xDtlsTransportParams;
    DtlsNetworkCredentials_t xNetworkCredentials;
} DtlsTestContext_t;

typedef struct IceControllerSignalingRemoteInfo
{
    /* Remote client ID is used to provide the destination of Signaling message. */
    uint8_t isUsed;
    char remoteUserName[ ICE_CONTROLLER_USER_NAME_LENGTH + 1 ];
    char remotePassword[ ICE_CONTROLLER_PASSWORD_LENGTH + 1 ];
    // Reserve 1 space for NULL terminator, the other one is for ':' between remote username & local username
    char combinedName[ ( ICE_CONTROLLER_USER_NAME_LENGTH << 1 ) + 2 ];
    char remoteClientId[ SIGNALING_CONTROLLER_REMOTE_ID_MAX_LENGTH ];
    size_t remoteClientIdLength;
    IceControllerSocketContext_t socketsContexts[ ICE_CONTROLLER_MAX_CANDIDATE_PAIR_COUNT ];
    size_t socketsContextsCount;

    /* For ICE component. */
    IceContext_t iceContext;
    IceCandidate_t localCandidatesBuffer[ ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t remoteCandidatesBuffer[ ICE_CONTROLLER_MAX_REMOTE_CANDIDATE_COUNT ];
    IceCandidatePair_t candidatePairsBuffer[ ICE_CONTROLLER_MAX_CANDIDATE_PAIR_COUNT ];
    TransactionIdStore_t transactionIdStore;
    TransactionIdSlot_t transactionIdsBuffer[ ICE_CONTROLLER_MAX_CANDIDATE_PAIR_COUNT ];
    IceCandidatePair_t * pNominationPair;

    /* For DTLS. */
    DtlsTestContext_t dtlsTestContext;
    mbedtls_x509_crt answerCert;
    mbedtls_pk_context answerKey;
    char answerCertFingerprint[CERTIFICATE_FINGERPRINT_LENGTH];
    unsigned char private_key_pcs_pem[PRIVATE_KEY_PCS_PEM_SIZE];
} IceControllerRemoteInfo_t;

typedef struct IceControllerDetectRxPacket
{
    IceControllerSocketContext_t * pSocketContext;
} IceControllerDetectRxPacket_t;

typedef enum IceControllerRequestType
{
    ICE_CONTROLLER_REQUEST_TYPE_NONE = 0,
    ICE_CONTROLLER_REQUEST_TYPE_ADD_REMOTE_CANDIDATE,
    ICE_CONTROLLER_REQUEST_TYPE_CONNECTIVITY_CHECK,
    ICE_CONTROLLER_REQUEST_TYPE_DETECT_RX_PACKET,
} IceControllerRequestType_t;

typedef struct IceControllerRequestMessage
{
    IceControllerRequestType_t requestType;

    /* Decode the request message based on request type. */
    union RequestContent_t
    {
        IceControllerCandidate_t remoteCandidate; /* ICE_CONTROLLER_REQUEST_TYPE_ADD_REMOTE_CANDIDATE */
        IceControllerRemoteInfo_t * pRemoteInfo; /* ICE_CONTROLLER_REQUEST_TYPE_CONNECTIVITY_CHECK */
        IceControllerDetectRxPacket_t detectRxPacket; /* ICE_CONTROLLER_REQUEST_TYPE_DETECT_RX_PACKET */
    } requestContent;
} IceControllerRequestMessage_t;

typedef struct IceControllerIceServer
{
    IceControllerIceServerType_t serverType; /* STUN or TURN */
    char url[ ICE_CONTROLLER_ICE_SERVER_URL_MAX_LENGTH ];
    size_t urlLength;
    IceEndpoint_t iceEndpoint; //IP address
    char userName[ ICE_CONTROLLER_ICE_SERVER_USERNAME_MAX_LENGTH ]; //user name
    size_t userNameLength;
    char password[ ICE_CONTROLLER_ICE_SERVER_PASSWORD_MAX_LENGTH ]; //password
    size_t passwordLength;
    IceSocketProtocol_t protocol; //tcp or udp
} IceControllerIceServer_t;

typedef struct IceControllerStunMsgHeader
{
    uint16_t msgType; //StunMessageType_t
    uint8_t contentLength[2];
    uint8_t magicCookie[ STUN_HEADER_MAGIC_COOKIE_OFFSET ];
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    uint8_t pStunAttributes[0];
} IceControllerStunMsgHeader_t;

typedef struct IceControllerSocketListenerContext
{
    int fds[ AWS_MAX_VIEWER_NUM * ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT ];
    size_t fdsCount;
    IceControllerSocketContext_t * pFdsMapContext[ AWS_MAX_VIEWER_NUM * ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT ]; /* To map corresponding socket context with fds. */

    SemaphoreHandle_t socketListenerMutex;
    uint8_t executeSocketListener;
} IceControllerSocketListenerContext_t;

typedef struct IceControllerContext
{
    /* The signaling controller context initialized by application. */
    SignalingControllerContext_t * pSignalingControllerContext;

    char localUserName[ ICE_CONTROLLER_USER_NAME_LENGTH + 1 ];
    char localPassword[ ICE_CONTROLLER_PASSWORD_LENGTH + 1 ];
    char localCname[ ICE_CONTROLLER_CNAME_LENGTH + 1 ];

    IceControllerRemoteInfo_t remoteInfo[ AWS_MAX_VIEWER_NUM ];
    IceEndpoint_t localEndpoints[ ICE_CONTROLLER_MAX_LOCAL_CANDIDATE_COUNT ];
    size_t localIceEndpointsCount;
    size_t candidateFoundationCounter;

    IceControllerIceServer_t iceServers[ SIGNALING_CONTROLLER_ICE_SERVER_MAX_ICE_CONFIG_COUNT + 1 ]; /* Reserve 1 space for default STUN server. */
    size_t iceServersCount;

    IceControllerMetrics_t metrics;

    TimerHandler_t connectivityCheckTimer;

    /* Request queue. */
    MessageQueueHandler_t requestQueue;

    IceControllerSocketListenerContext_t socketListenerContext;
} IceControllerContext_t;

#ifdef __cplusplus
}
#endif

#endif /* ICE_CONTROLLER_DATA_TYPES_H */
