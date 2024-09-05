#ifndef PEER_CONNECTION_DATA_TYPES_H
#define PEER_CONNECTION_DATA_TYPES_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "transport_dtls_mbedtls.h"

#include "message_queue.h"
#include "ice_controller.h"
#include "transceiver_data_types.h"

#include "srtp.h"
#include "rtp_data_types.h"
#include "rtp_pkt_queue.h"
#include "rtcp_data_types.h"

#define PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ( 2 )
#define PEER_CONNECTION_USER_NAME_LENGTH ( 4 )
#define PEER_CONNECTION_PASSWORD_LENGTH ( 24 )
#define PEER_CONNECTION_CNAME_LENGTH ( 16 )
#define PEER_CONNECTION_CERTIFICATE_FINGERPRINT_LENGTH ( CERTIFICATE_FINGERPRINT_LENGTH )
#define PEER_CONNECTION_JITTER_BUFFER_MAX_ENTRY_NUM ( 1000 )
#define PEER_CONNECTION_FRAME_BUFFER_SIZE ( 4096 )

#define PEER_CONNECTION_FRAME_CURRENT_VERSION ( 0 )

typedef enum PeerConnectionResult
{
    PEER_CONNECTION_RESULT_OK = 0,
    PEER_CONNECTION_RESULT_BAD_PARAMETER,
    PEER_CONNECTION_RESULT_NO_FREE_TRANSCEIVER,
    PEER_CONNECTION_RESULT_NO_AVAILABLE_SESSION,
    PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_CONTROLLER,
    PEER_CONNECTION_RESULT_FAIL_CREATE_TASK_ICE_SOCK_LISTENER,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_INIT,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_START,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_ADD_REMOTE_CANDIDATE,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_CONNECTIVITY_CHECK,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESTROY,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_DESERIALIZE_CANDIDATE,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_REMOTE_CANDIDATE,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_SEND_RTP_PACKET,
    PEER_CONNECTION_RESULT_FAIL_ICE_CONTROLLER_RESEND_RTP_PACKET,
    PEER_CONNECTION_RESULT_FAIL_CREATE_CERT_AND_KEY,
    PEER_CONNECTION_RESULT_FAIL_CREATE_CERT_FINGERPRINT,
    PEER_CONNECTION_RESULT_FAIL_WRITE_KEY_PEM,
    PEER_CONNECTION_RESULT_FAIL_MQ_INIT,
    PEER_CONNECTION_RESULT_FAIL_MQ_SEND,
    PEER_CONNECTION_RESULT_FAIL_CREATE_SRTP_RX_SESSION,
    PEER_CONNECTION_RESULT_FAIL_CREATE_SRTP_TX_SESSION,
    PEER_CONNECTION_RESULT_FAIL_ENCRYPT_SRTP_RTP_PACKET,
    PEER_CONNECTION_RESULT_FAIL_DECRYPT_SRTP_RTP_PACKET,
    PEER_CONNECTION_RESULT_FAIL_RTP_INIT,
    PEER_CONNECTION_RESULT_FAIL_RTP_SERIALIZE,
    PEER_CONNECTION_RESULT_FAIL_RTP_DESERIALIZE,
    PEER_CONNECTION_RESULT_FAIL_RTP_RX_NO_MATCHING_SSRC,
    PEER_CONNECTION_RESULT_FAIL_RTCP_INIT,
    PEER_CONNECTION_RESULT_FAIL_RTCP_DESERIALIZE,
    PEER_CONNECTION_RESULT_FAIL_RTCP_PARSE_NACK,
    PEER_CONNECTION_RESULT_FAIL_CREATE_SENDER_MUTEX,
    PEER_CONNECTION_RESULT_FAIL_TAKE_SENDER_MUTEX,
    PEER_CONNECTION_RESULT_FAIL_ROLLING_BUFFER_SEQ_NOT_FOUND,
    PEER_CONNECTION_RESULT_FAIL_ROLLING_BUFFER_NO_ENOUGH_MEMORY,
    PEER_CONNECTION_RESULT_FAIL_PACKET_INFO_NO_ENOUGH_MEMORY,
    PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_QUEUE_INIT,
    PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_QUEUE_RETRIEVE,
    PEER_CONNECTION_RESULT_FAIL_RTP_PACKET_ENQUEUE,
    PEER_CONNECTION_RESULT_FAIL_PACKETIZER_INIT,
    PEER_CONNECTION_RESULT_FAIL_PACKETIZER_ADD_FRAME,
    PEER_CONNECTION_RESULT_FAIL_PACKETIZER_GET_PACKET,
    PEER_CONNECTION_RESULT_FAIL_DEPACKETIZER_INIT,
    PEER_CONNECTION_RESULT_FAIL_DEPACKETIZER_GET_PROPERTIES,
    PEER_CONNECTION_RESULT_FAIL_DEPACKETIZER_ADD_PACKET,
    PEER_CONNECTION_RESULT_FAIL_DEPACKETIZER_GET_FRAME,
    PEER_CONNECTION_RESULT_FAIL_JITTER_BUFFER_SEQ_NOT_FOUND,
    PEER_CONNECTION_RESULT_UNKNOWN_SRTP_PROFILE,
    PEER_CONNECTION_RESULT_UNKNOWN_TX_CODEC,
    PEER_CONNECTION_RESULT_UNKNOWN_SSRC,
    PEER_CONNECTION_RESULT_PACKET_OUTDATED,
} PeerConnectionResult_t;

typedef struct PeerConnectionFrame
{
    uint32_t version;
    uint8_t * pData;
    size_t dataLength;
    uint64_t presentationUs;
} PeerConnectionFrame_t;

typedef struct PeerConnectionJitterBufferPacket PeerConnectionJitterBufferPacket_t;
typedef struct PeerConnectionJitterBuffer PeerConnectionJitterBuffer_t;

typedef PeerConnectionResult_t (* OnFrameReadyCallback_t)( void * pCustomContext,
                                                           PeerConnectionFrame_t * pFrame );
typedef PeerConnectionResult_t (* OnJitterBufferFrameReadyCallback_t)( void * pCustomContext,
                                                                       uint16_t startSequence,
                                                                       uint16_t endSequence );
typedef PeerConnectionResult_t (* OnJitterBufferFrameDropCallback_t)( void * pCustomContext,
                                                                      uint16_t startSequence,
                                                                      uint16_t endSequence );
typedef PeerConnectionResult_t (* GetPacketPropertyFunc_t)( PeerConnectionJitterBufferPacket_t * pPacket,
                                                            uint8_t * pIsStartPacket );
typedef PeerConnectionResult_t (* FillFrameFunc_t)( PeerConnectionJitterBuffer_t * pJitterBuffer,
                                                    uint16_t rtpSeqStart,
                                                    uint16_t rtpSeqEnd,
                                                    uint8_t * pOutBuffer,
                                                    size_t * pOutBufferLength );

typedef struct PeerConnectionRollingBufferPacket
{
    RtpPacket_t rtpPacket;
    uint8_t * pPacketBuffer;
    size_t packetBufferLength;
} PeerConnectionRollingBufferPacket_t;

typedef struct PeerConnectionRollingBuffer
{
    RtpPacketQueue_t packetQueue;
    size_t maxSizePerPacket;
    size_t capacity; /* Buffer duration * highest expected bitrate (in bps) / 8 / maxPacketSize. */
} PeerConnectionRollingBuffer_t;

typedef struct PeerConnectionJitterBufferPacket
{
    uint8_t isPushed;
    uint16_t sequenceNumber;
    uint32_t rtpTimestamp;
    TickType_t receiveTick;
    uint8_t * pPacketBuffer;
    size_t packetBufferLength;
} PeerConnectionJitterBufferPacket_t;

typedef struct PeerConnectionJitterBuffer
{
    uint8_t isStart; /* The jitter buffer starts to receive packet or not. */
    size_t capacity; /* The total number of packets that packet queue can store. */
    uint32_t clockRate; /* The clock rate based on the codec. For example: the clock rate is 90000 if the chosen RTP is H264/90000. */
    uint32_t codec; /* The codec. For example: the codec is set to H264 if the chosen RTP is H264/90000. */
    uint32_t tolerenceRtpTimeStamp; /* The buffer time in RTP time stamp format. */
    uint32_t lastPopRtpTimestamp; /* The timestamp in last pop RTP packet. */
    TickType_t lastPopTick; /* The receive time ticks in last pop RTP packet. */
    uint16_t lastPopSequenceNumber; /* The RTP sequence number in last pop RTP packet. */
    uint16_t oldestReceivedSequenceNumber; /* The oldest RTP sequence number that received in the packet queue. */
    uint16_t newestReceivedSequenceNumber; /* The newest RTP sequence number that received in the packet queue. */
    uint32_t newestReceivedTimestamp; /* The newest timestamp in packet queue. */
    PeerConnectionJitterBufferPacket_t rtpPackets[ PEER_CONNECTION_JITTER_BUFFER_MAX_ENTRY_NUM ]; /* The buffer for packet queue. */

    /* Callback functions & custom contexts. */
    OnJitterBufferFrameReadyCallback_t onFrameReadyCallbackFunc;
    void * pOnFrameReadyCallbackContext;
    OnJitterBufferFrameDropCallback_t onFrameDropCallbackFunc;
    void * pOnFrameDropCallbackContext;
    GetPacketPropertyFunc_t getPacketPropertyFunc;
    FillFrameFunc_t fillFrameFunc;
} PeerConnectionJitterBuffer_t;

typedef struct PeerConnectionRemoteInfo
{
    const char * pRemoteClientId; /* From SignalingControllerReceiveEvent_t */
    size_t remoteClientIdLength;
    const char * pRemoteUserName; /* From ice-ufrag in SDP attributes */
    size_t remoteUserNameLength;
    const char * pRemotePassword; /* From ice-pwd in SDP attributes */
    size_t remotePasswordLength;
    const char * pRemoteCertFingerprint; /* From fingerprint in SDP attributes */
    size_t remoteCertFingerprintLength;
    uint8_t isVideoCodecPayloadSet;
    uint8_t isAudioCodecPayloadSet;
    uint32_t videoCodecPayload;
    uint32_t audioCodecPayload;
    uint8_t isVideoCodecRtxPayloadSet;
    uint8_t isAudioCodecRtxPayloadSet;
    uint32_t videoCodecRtxPayload;
    uint32_t audioCodecRtxPayload;
    uint16_t twccId;
    uint32_t remoteVideoSsrc;
    uint32_t remoteAudioSsrc;
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

typedef enum PeerConnectionSessionRequestType
{
    PEER_CONNECTION_SESSION_REQUEST_TYPE_NONE = 0,
    PEER_CONNECTION_SESSION_REQUEST_TYPE_ADD_REMOTE_CANDIDATE,
    PEER_CONNECTION_SESSION_REQUEST_TYPE_CONNECTIVITY_CHECK,
} PeerConnectionSessionRequestType_t;

typedef struct PeerConnectionSessionRequestMessage
{
    PeerConnectionSessionRequestType_t requestType;

    /* Decode the request message based on request type. */
    union
    {
        IceControllerCandidate_t remoteCandidate; /* PEER_CONNECTION_SESSION_REQUEST_TYPE_ADD_REMOTE_CANDIDATE */
    } peerConnectionSessionRequestContent;
} PeerConnectionSessionRequestMessage_t;

typedef enum PeerConnectionSessionState
{
    PEER_CONNECTION_SESSION_STATE_NONE = 0,
    PEER_CONNECTION_SESSION_STATE_START,
    PEER_CONNECTION_SESSION_STATE_P2P_CONNECTION_FOUND,
    PEER_CONNECTION_SESSION_STATE_CONNECTION_READY,
} PeerConnectionSessionState_t;

typedef struct PeerConnectionRtpConfig
{
    uint8_t isVideoCodecPayloadSet;
    uint8_t isAudioCodecPayloadSet;
    uint16_t videoSequenceNumber;
    uint16_t audioSequenceNumber;
    uint32_t videoCodecPayload;
    uint32_t audioCodecPayload;
    uint32_t videoCodecRtxPayload;
    uint32_t audioCodecRtxPayload;
    uint16_t videoRtxSequenceNumber;
    uint16_t audioRtxSequenceNumber;

    uint16_t twccId;
    uint16_t twccSequence;

    uint32_t remoteVideoSsrc;
    uint32_t remoteAudioSsrc;
} PeerConnectionRtpConfig_t;

typedef struct PeerConnectionSrtpSender
{
    /* RTP Tx rolling buffer. */
    PeerConnectionRollingBuffer_t txRollingBuffer;

    /* Mutex to protect sender info like rolling buffer. */
    SemaphoreHandle_t senderMutex;
} PeerConnectionSrtpSender_t;

typedef struct PeerConnectionSrtpReceiver
{
    /* RTP Rx jitter buffer. */
    PeerConnectionJitterBuffer_t rxJitterBuffer;
    uint8_t frameBuffer[ PEER_CONNECTION_FRAME_BUFFER_SIZE ];

    OnFrameReadyCallback_t onFrameReadyCallbackFunc;
    void * pOnFrameReadyCallbackCustomContext;
} PeerConnectionSrtpReceiver_t;

typedef struct PeerConnectionContext PeerConnectionContext_t;

typedef struct PeerConnectionSession
{
    PeerConnectionSessionState_t state;

    /* The signaling controller context initialized by application. */
    SignalingControllerContext_t * pSignalingControllerContext;
    TaskHandle_t * pTaskHandler;

    /* The remote client ID, representing the remote peer, from signaling message. */
    char remoteClientId[ SIGNALING_CONTROLLER_REMOTE_ID_MAX_LENGTH ];
    size_t remoteClientIdLength;
    /* The remote user name, representing the remote peer, from SDP message. */
    char remoteUserName[ PEER_CONNECTION_USER_NAME_LENGTH + 1 ];
    /* The remote password, representing password of the remote peer, from SDP message. */
    char remotePassword[ PEER_CONNECTION_PASSWORD_LENGTH + 1 ];
    /* The combine name to respond back in SDP message.
     * Reserve 1 space for NULL terminator, the other one is for ':' between remote username & local username */
    char combinedName[ ( PEER_CONNECTION_USER_NAME_LENGTH << 1 ) + 2 ];
    /* The remote cert fingerprint from SDP message. */
    char remoteCertFingerprint[ PEER_CONNECTION_CERTIFICATE_FINGERPRINT_LENGTH + 1 ];
    size_t remoteCertFingerprintLength;

    IceControllerContext_t iceControllerContext;

    /* Request queue. */
    MessageQueueHandler_t requestQueue;

    /* DTLS session. */
    DtlsSession_t dtlsSession;
    /* SRTP sessions. */
    srtp_t srtpTransmitSession;
    srtp_t srtpReceiveSession;
    /* RTP config. */
    PeerConnectionRtpConfig_t rtpConfig;

    PeerConnectionSrtpSender_t videoSrtpSender;
    PeerConnectionSrtpSender_t audioSrtpSender;
    PeerConnectionSrtpReceiver_t videoSrtpReceiver;
    PeerConnectionSrtpReceiver_t audioSrtpReceiver;

    /* Pointer that points to peer connection context. */
    PeerConnectionContext_t * pCtx;
} PeerConnectionSession_t;

typedef struct PeerConnectionDtlsContext
{
    uint8_t isInitialized;
    mbedtls_x509_crt localCert;
    mbedtls_pk_context localKey;
    char localCertFingerprint[CERTIFICATE_FINGERPRINT_LENGTH];
    unsigned char privateKeyPcsPem[PRIVATE_KEY_PCS_PEM_SIZE];
} PeerConnectionDtlsContext_t;

typedef struct PeerConnectionContext
{
    char localUserName[ PEER_CONNECTION_USER_NAME_LENGTH + 1 ];
    char localPassword[ PEER_CONNECTION_PASSWORD_LENGTH + 1 ];
    char localCname[ PEER_CONNECTION_CNAME_LENGTH + 1 ];

    const Transceiver_t * pTransceivers[ PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ];
    uint32_t transceiverCount;

    /* DTLS cert/key/fingerprint. */
    PeerConnectionDtlsContext_t dtlsContext;
    RtpContext_t rtpContext;
    RtcpContext_t rtcpContext;

    PeerConnectionSession_t peerConnectionSessions[ AWS_MAX_VIEWER_NUM ];
} PeerConnectionContext_t;

#ifdef __cplusplus
}
#endif

#endif /* PEER_CONNECTION_DATA_TYPES_H */
