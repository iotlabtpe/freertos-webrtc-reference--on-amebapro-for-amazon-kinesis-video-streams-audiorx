#ifndef TRANSCEIVER_DATA_TYPES_H
#define TRANSCEIVER_DATA_TYPES_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Standard includes. */
#include <stdio.h>

#define TRANSCEIVER_STREAM_ID_MAX_LENGTH ( 256 )
#define TRANSCEIVER_TRACK_ID_MAX_LENGTH ( 256 )

typedef enum TransceiverRtcCodec
{
    TRANSCEIVER_RTC_CODEC_PAYLOAD_MULAW = 0,
    TRANSCEIVER_RTC_CODEC_PAYLOAD_ALAW = 8,
    TRANSCEIVER_RTC_CODEC_PAYLOAD_VP8 = 96,
    TRANSCEIVER_RTC_CODEC_PAYLOAD_OPUS = 111,
    TRANSCEIVER_RTC_CODEC_PAYLOAD_H264 = 125,
    TRANSCEIVER_RTC_CODEC_PAYLOAD_H265 = 127,
} TransceiverRtcCodec_t;

typedef enum TransceiverRtcCodecBit
{
    TRANSCEIVER_RTC_CODEC_UNKNOWN_BIT = 0,
    TRANSCEIVER_RTC_CODEC_MULAW_BIT = 1 << 0,
    TRANSCEIVER_RTC_CODEC_ALAW_BIT = 1 << 1,
    TRANSCEIVER_RTC_CODEC_VP8_BIT = 1 << 2,
    TRANSCEIVER_RTC_CODEC_OPUS_BIT = 1 << 3,
    TRANSCEIVER_RTC_CODEC_H264_BIT = 1 << 4,
    TRANSCEIVER_RTC_CODEC_H265_BIT = 1 << 5,
    TRANSCEIVER_RTC_CODEC_AAC_BIT = 1 << 6,
} TransceiverRtcCodecBit_t;

typedef enum TransceiverTrackKind
{
    TRANSCEIVER_TRACK_KIND_UNKNOWN = 0,
    TRANSCEIVER_TRACK_KIND_AUDIO, //!< Audio track. Track information is set before add transceiver
    TRANSCEIVER_TRACK_KIND_VIDEO, //!< Video track. Track information is set before add transceiver
} TransceiverTrackKind_t;

typedef enum TransceiverDirection
{
    TRANSCEIVER_TRACK_DIRECTION_UNKNOWN = 0,
    TRANSCEIVER_TRACK_DIRECTION_SENDRECV,
    TRANSCEIVER_TRACK_DIRECTION_SENDONLY,
    TRANSCEIVER_TRACK_DIRECTION_RECVONLY,
    TRANSCEIVER_TRACK_DIRECTION_INACTIVE,
} TransceiverDirection_t;

typedef struct Transceiver
{
    TransceiverTrackKind_t trackKind;
    TransceiverDirection_t direction;
    uint32_t codecBitMap; // Use TransceiverRtcCodecBit_t to set corresponding bits
    uint32_t rollingbufferDurationSec;
    uint32_t rollingbufferBitRate; // bps
    char streamId[ TRANSCEIVER_STREAM_ID_MAX_LENGTH ];
    size_t streamIdLength;
    char trackId[ TRANSCEIVER_TRACK_ID_MAX_LENGTH ];
    size_t trackIdLength;
} Transceiver_t;

#ifdef __cplusplus
}
#endif

#endif /* TRANSCEIVER_DATA_TYPES_H */
