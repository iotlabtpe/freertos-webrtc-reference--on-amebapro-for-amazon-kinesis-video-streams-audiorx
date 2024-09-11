#include <stdlib.h>
#include "logging.h"
#include "sdp_controller.h"
#include "core_json.h"
#include "sdp_deserializer.h"
#include "sdp_serializer.h"
#include "string_utils.h"
#include "peer_connection.h"

#define SDP_CONTROLLER_ORIGIN_DEFAULT_USER_NAME "-"
#define SDP_CONTROLLER_ORIGIN_DEFAULT_SESSION_VERSION ( 2 )
#define SDP_CONTROLLER_ORIGIN_DEFAULT_NET_TYPE "IN"
#define SDP_CONTROLLER_ORIGIN_IPV4_TYPE "IP4"
#define SDP_CONTROLLER_ORIGIN_DEFAULT_IP_ADDRESS "127.0.0.1"

#define SDP_CONTROLLER_SDP_OFFER_MESSAGE_TYPE_KEY "type"
#define SDP_CONTROLLER_SDP_OFFER_MESSAGE_TYPE_VALUE "offer"
#define SDP_CONTROLLER_SDP_OFFER_MESSAGE_CONTENT_KEY "sdp"
#define SDP_CONTROLLER_SDP_NEWLINE_ENDING "\\n"

#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP "setup"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP_LENGTH ( 5 )
#define SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE "active"
#define SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE_LENGTH ( 6 )
#define SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTPASS "actpass"
#define SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTPASS_LENGTH ( 7 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MSID "msid"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MSID_LENGTH ( 4 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP "rtcp"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_LENGTH ( 4 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP "9 IN IP4 0.0.0.0"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_LENGTH ( 16 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG "ice-ufrag"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG_LENGTH ( 9 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD "ice-pwd"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD_LENGTH ( 7 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION "ice-options"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION_LENGTH ( 11 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION "trickle"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION_LENGTH ( 7 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT "fingerprint"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT_LENGTH ( 11 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC "ssrc"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC_LENGTH ( 4 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID "mid"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID_LENGTH ( 3 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV "sendrecv"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY "sendonly"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY "recvonly"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE "inactive"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_MUX "rtcp-mux"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_MUX_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_RSIZE "rtcp-rsize"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_RSIZE_LENGTH ( 10 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP "rtpmap"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH ( 6 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H264 "H264/90000"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H264_LENGTH ( 10 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_OPUS "opus/48000/2"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_OPUS_LENGTH ( 12 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_VP8 "VP8/90000"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_VP8_LENGTH ( 9 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_MULAW "PCMU/8000"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_MULAW_LENGTH ( 9 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_ALAW "PCMA/8000"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_ALAW_LENGTH ( 9 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H265 "H265/90000"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H265_LENGTH ( 10 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB "rtcp-fb"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB_LENGTH ( 7 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H264 "nack pli"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H264_LENGTH ( 8 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H265 SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H264
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H265_LENGTH SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H264_LENGTH
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_GOOG_REMB "goog-remb"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_GOOG_REMB_LENGTH ( 9 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP "fmtp"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ( 4 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_EXTMAP "extmap"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_EXTMAP_LENGTH ( 6 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL_LENGTH ( 73 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_TRANSPORT_CC "transport-cc"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_TRANSPORT_CC_LENGTH ( 12 )
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_CANDIDATE "candidate"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_CANDIDATE_LENGTH ( 9 )

#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_OPUS "minptime=10;useinbandfec=1"
#define SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_H265 "profile-space=0;profile-id=0;tier-flag=0;level-id=0;interop-constraints=000000000000;sprop-vps=QAEMAf//" \
    "AIAAAAMAAAMAAAMAAAMAALUCQA==;sprop-sps=QgEBAIAAAAMAAAMAAAMAAAMAAKACgIAtH+W1kkbQzkkktySqSfKSyA==;sprop-pps=RAHBpVgeSA=="

#define SDP_CONTROLLER_H264_PACKETIZATION_MODE "packetization-mode=1"
#define SDP_CONTROLLER_H264_PACKETIZATION_MODE_LENGTH ( 20 )
#define SDP_CONTROLLER_H264_ASYMMETRY_ALLOWED "level-asymmetry-allowed=1"
#define SDP_CONTROLLER_H264_ASYMMETRY_ALLOWED_LENGTH ( 25 )
#define SDP_CONTROLLER_H264_PROFILE_LEVEL_ID "profile-level-id="
#define SDP_CONTROLLER_H264_PROFILE_LEVEL_ID_LENGTH ( 17 )

#define SDP_CONTROLLER_MAX_FMTP_APT_NUM ( 64 )

#define SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( payload ) ( payload & 0xFF )
#define SDP_CONTROLLER_GET_RTX_CODEC_FROM_PAYLOAD( payload ) ( payload >> 16 )
#define SDP_CONTROLLER_SET_PAYLOAD( rtxPayload, aptPayload ) ( rtxPayload << 16 | aptPayload )

// profile-level-id:
//   A base16 [7] (hexadecimal) representation of the following
//   three bytes in the sequence parameter set NAL unit is specified
//   in [1]: 1) profile_idc, 2) a byte herein referred to as
//   profile-iop, composed of the values of constraint_set0_flag,
//   constraint_set1_flag, constraint_set2_flag,
//   constraint_set3_flag, constraint_set4_flag,
//   constraint_set5_flag, and reserved_zero_2bits in bit-
//   significance order, starting from the most-significant bit, and
//   3) level_id.
//
// Reference: https://tools.ietf.org/html/rfc6184#section-8.1
#define SDP_CONTROLLER_H264_PROFILE_42E01F 0x42e01f
#define SDP_CONTROLLER_H264_FMTP_SUBPROFILE_MASK 0xFFFF00
#define SDP_CONTROLLER_H264_FMTP_PROFILE_LEVEL_MASK 0x0000FF
#define SDP_CONTROLLER_H264_FMTP_MINIMUM_SCORE ( 10 )
#define SDP_CONTROLLER_H264_FMTP_HIGHEST_SCORE ( 12 )

#define SDP_CONTROLLER_CODEC_H264_VALUE "H264/90000"
#define SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH ( 10 )
#define SDP_CONTROLLER_CODEC_H265_VALUE "H265/90000"
#define SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH ( 10 )
#define SDP_CONTROLLER_CODEC_OPUS_VALUE "opus/48000/2"
#define SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH ( 12 )
#define SDP_CONTROLLER_CODEC_VP8_VALUE "VP8/90000"
#define SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH ( 9 )
#define SDP_CONTROLLER_CODEC_MULAW_VALUE "PCMU/8000"
#define SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH ( 9 )
#define SDP_CONTROLLER_CODEC_ALAW_VALUE "PCMA/8000"
#define SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH ( 9 )
#define SDP_CONTROLLER_CODEC_RTX_VALUE "rtx/90000"
#define SDP_CONTROLLER_CODEC_RTX_VALUE_LENGTH ( 9 )
#define SDP_CONTROLLER_CODEC_APT_VALUE "apt="
#define SDP_CONTROLLER_CODEC_APT_VALUE_LENGTH ( 4 )

#define SDP_CONTROLLER_CODEC_MULAW_DEFAULT_INDEX "0"
#define SDP_CONTROLLER_CODEC_MULAW_DEFAULT_INDEX_LENGTH ( 1 )
#define SDP_CONTROLLER_CODEC_ALAW_DEFAULT_INDEX "8"
#define SDP_CONTROLLER_CODEC_ALAW_DEFAULT_INDEX_LENGTH ( 1 )

static SdpControllerResult_t ParseExtraAttributes( SdpControllerSdpDescription_t * pOffer,
                                                   SdpAttribute_t * pAttribute );
static SdpControllerResult_t parseMediaAttributes( SdpControllerSdpDescription_t * pOffer,
                                                   const char * pAttributeBuffer,
                                                   size_t attributeBufferLength );
static SdpControllerResult_t parseSessionAttributes( SdpControllerSdpDescription_t * pOffer,
                                                     const char * pAttributeBuffer,
                                                     size_t attributeBufferLength );
static SdpControllerResult_t serializeOrigin( SdpSerializerContext_t * pCtx,
                                              SdpControllerOrigin_t * pOrigin );
static SdpControllerResult_t serializeTiming( SdpSerializerContext_t * pCtx,
                                              SdpControllerTiming_t * pTiming );
static SdpControllerResult_t serializeAttributes( SdpSerializerContext_t * pCtx,
                                                  SdpControllerAttributes_t * pAttributes,
                                                  uint16_t attributeCount );
static SdpControllerResult_t serializeConnectionInfo( SdpSerializerContext_t * pCtx,
                                                      SdpControllerConnectionInformation_t * pConnectionInfo );
static SdpControllerResult_t serializeMedias( SdpSerializerContext_t * pCtx,
                                              SdpControllerMediaDescription_t * pMediaDescriptions,
                                              uint16_t mediaCount );
static SdpControllerResult_t serializeSdpMessage( SdpControllerSdpDescription_t * pSdpDescription,
                                                  char * pOutputBuffer,
                                                  size_t * pOutputBufferSize );
static SdpControllerResult_t PopulateTransceiverSsrc( char ** ppBuffer,
                                                      size_t * pBufferLength,
                                                      SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                      const Transceiver_t * pTransceiver,
                                                      const char * pCname,
                                                      size_t cnameLength );
static SdpControllerResult_t PopulateRtcpFb( char ** ppBuffer,
                                             size_t * pBufferLength,
                                             SdpControllerSdpDescription_t * pSdpLocalDescription,
                                             uint32_t codec,
                                             uint16_t twccId );
static SdpControllerResult_t PopulateCodecAttributesH264Profile42E01FLevelAsymmetryAllowedPacketization( char ** ppBuffer,
                                                                                                         size_t * pBufferLength,
                                                                                                         SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                                                                         SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                                                                         const Transceiver_t * pTransceiver,
                                                                                                         uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributesOpus( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributesVp8( char ** ppBuffer,
                                                         size_t * pBufferLength,
                                                         SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                         SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                         const Transceiver_t * pTransceiver,
                                                         uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributesMulaw( char ** ppBuffer,
                                                           size_t * pBufferLength,
                                                           SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                           SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                           const Transceiver_t * pTransceiver,
                                                           uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributesAlaw( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributesH265( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec );
static SdpControllerResult_t PopulateCodecAttributes( char ** ppBuffer,
                                                      size_t * pBufferLength,
                                                      SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                      SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                      const Transceiver_t * pTransceiver,
                                                      uint32_t codec );
static const SdpControllerAttributes_t * FindAttributeName( const SdpControllerAttributes_t * pAttributes,
                                                            size_t attributeCount,
                                                            char * pPattern,
                                                            size_t patternLength );
static const SdpControllerAttributes_t * FindFmtpBasedOnCodec( const SdpControllerAttributes_t * pAttributes,
                                                               size_t attributeCount,
                                                               uint32_t codec );
static SdpControllerResult_t PopulateSingleMedia( char ** ppBuffer,
                                                  size_t * pBufferLength,
                                                  SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                  SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                  const Transceiver_t * pTransceiver,
                                                  PeerConnectionContext_t * pPeerConnectionContext,
                                                  uint32_t chosenCodec,
                                                  const char * pLocalFingerprint,
                                                  size_t localFingerprintLength );
static uint32_t CollectAttributesCodecBitMap( SdpControllerAttributes_t * pAttributes,
                                              uint8_t attributeCount,
                                              uint32_t * pCodecPayloads,
                                              size_t codecPayloadsSize,
                                              uint32_t * pRtxCodecPayloads,
                                              size_t * pRtxCodecPayloadsSize );
static const Transceiver_t * OccupyProperTransceiver( SdpControllerMediaDescription_t * pRemoteMediaDescription,
                                                      const Transceiver_t * pTransceivers[],
                                                      size_t transceiversCount,
                                                      uint8_t * pIsTransceiverPopulated,
                                                      uint32_t * pChosenCodec );
static uint32_t GetDefaultCodec( uint32_t codecBitMap );

static SdpControllerResult_t ParseExtraAttributes( SdpControllerSdpDescription_t * pOffer,
                                                   SdpAttribute_t * pAttribute )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    StringUtilsResult_t stringResult;

    if( ( pOffer == NULL ) ||
        ( pAttribute == NULL ) )
    {
        LogError( ( "Fail to parse extra attributes, pOffer: %p, pAttribute: %p", pOffer, pAttribute ) );
        ret = SDP_CONTROLLER_RESULT_SDP_SESSION_ATTRIBUTE_MAX_EXCEDDED;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Checking extra attributes info. */
        if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT_LENGTH ) &&
            ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT_LENGTH ) == 0 ) )
        {
            /* Found fingerprint, store it as extra info. */
            pOffer->quickAccess.pFingerprint = pAttribute->pAttributeValue;
            pOffer->quickAccess.fingerprintLength = pAttribute->attributeValueLength;
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP_LENGTH ) == 0 ) )
        {
            /* Found setup, store it as extra info. */
            if( ( pAttribute->attributeValueLength == SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE_LENGTH ) &&
                ( strncmp( SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE_LENGTH ) == 0 ) )
            {
                pOffer->quickAccess.dtlsRole = SDP_CONTROLLER_DTLS_ROLE_ACTIVE;
            }
            else
            {
                pOffer->quickAccess.dtlsRole = SDP_CONTROLLER_DTLS_ROLE_ACTPASS;
            }
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION_LENGTH ) == 0 ) &&
                 ( pAttribute->attributeValueLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION, pAttribute->pAttributeValue, SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION_LENGTH ) == 0 ) )
        {
            pOffer->quickAccess.isIceTrickle = 1U;
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG_LENGTH ) == 0 ) )
        {
            pOffer->quickAccess.pIceUfrag = pAttribute->pAttributeValue;
            pOffer->quickAccess.iceUfragLength = pAttribute->attributeValueLength;
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD_LENGTH ) == 0 ) )
        {
            pOffer->quickAccess.pIcePwd = pAttribute->pAttributeValue;
            pOffer->quickAccess.icePwdLength = pAttribute->attributeValueLength;
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_EXTMAP_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_EXTMAP, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_EXTMAP_LENGTH ) == 0 ) &&
                 ( pAttribute->attributeValueLength > SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL_LENGTH ) )
        {
            /* The attribute value length is confirmed larger than URL. */
            size_t length = pAttribute->attributeValueLength - SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL_LENGTH;
            const char * pFindStart = pAttribute->pAttributeValue + length;
            if( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL, pFindStart, SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_TWCC_EXT_URL_LENGTH ) == 0 )
            {
                /* Found TWCC ext URL. */
                stringResult = StringUtils_ConvertStringToUl( pAttribute->pAttributeValue, length, &pOffer->quickAccess.twccExtId );
                if( stringResult != STRING_UTILS_RESULT_OK )
                {
                    LogError( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                stringResult,
                                ( int ) length, pAttribute->pAttributeValue,
                                pOffer->quickAccess.twccExtId ) );
                    ret = SDP_CONTROLLER_RESULT_SDP_INVALID_TWCC_ID;
                }
                else
                {
                    LogDebug( ( "Found TWCC, ID: %lu", pOffer->quickAccess.twccExtId ) );
                }
            }
        }
        else if( ( pAttribute->attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_CANDIDATE_LENGTH ) &&
                 ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_CANDIDATE, pAttribute->pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_CANDIDATE_LENGTH ) == 0 ) )
        {
            /* Got a remote candidate from remote SDP */
            if( pOffer->quickAccess.pRemoteCandidate == NULL )
            {
                pOffer->quickAccess.pRemoteCandidate = pAttribute->pAttributeValue;
                pOffer->quickAccess.remoteCandidateLength = pAttribute->attributeValueLength;
            }
        }
    }

    return ret;
}

static SdpControllerResult_t parseMediaAttributes( SdpControllerSdpDescription_t * pOffer,
                                                   const char * pAttributeBuffer,
                                                   size_t attributeBufferLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpAttribute_t attribute;
    uint8_t mediaIndex = pOffer->mediaCount - 1;
    uint8_t * pAttributeCount = &pOffer->mediaDescriptions[ mediaIndex ].mediaAttributesCount;

    if( pOffer->mediaDescriptions[ mediaIndex ].mediaAttributesCount >= SDP_CONTROLLER_MAX_SDP_ATTRIBUTES_COUNT )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_MEDIA_ATTRIBUTE_MAX_EXCEDDED;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        sdpResult = SdpDeserializer_ParseAttribute( pAttributeBuffer, attributeBufferLength, &attribute );
        if( sdpResult != SDP_RESULT_OK )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_DESERIALIZER_PARSE_ATTRIBUTE;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pOffer->mediaDescriptions[ mediaIndex ].attributes[ *pAttributeCount ].pAttributeName = attribute.pAttributeName;
        pOffer->mediaDescriptions[ mediaIndex ].attributes[ *pAttributeCount ].attributeNameLength = attribute.attributeNameLength;
        pOffer->mediaDescriptions[ mediaIndex ].attributes[ *pAttributeCount ].pAttributeValue = attribute.pAttributeValue;
        pOffer->mediaDescriptions[ mediaIndex ].attributes[ *pAttributeCount ].attributeValueLength = attribute.attributeValueLength;
        ( *pAttributeCount )++;
    }

    /* Parse extra attributes to accerlate SDP creation later. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        ret = ParseExtraAttributes( pOffer, &attribute );
    }

    return ret;
}

static SdpControllerResult_t parseSessionAttributes( SdpControllerSdpDescription_t * pOffer,
                                                     const char * pAttributeBuffer,
                                                     size_t attributeBufferLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpAttribute_t attribute;

    if( pOffer->sessionAttributesCount >= SDP_CONTROLLER_MAX_SDP_ATTRIBUTES_COUNT )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_SESSION_ATTRIBUTE_MAX_EXCEDDED;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        sdpResult = SdpDeserializer_ParseAttribute( pAttributeBuffer, attributeBufferLength, &attribute );
        if( sdpResult != SDP_RESULT_OK )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_DESERIALIZER_PARSE_ATTRIBUTE;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pOffer->attributes[ pOffer->sessionAttributesCount ].pAttributeName = attribute.pAttributeName;
        pOffer->attributes[ pOffer->sessionAttributesCount ].attributeNameLength = attribute.attributeNameLength;
        pOffer->attributes[ pOffer->sessionAttributesCount ].pAttributeValue = attribute.pAttributeValue;
        pOffer->attributes[ pOffer->sessionAttributesCount ].attributeValueLength = attribute.attributeValueLength;
        pOffer->sessionAttributesCount++;
    }

    /* Parse extra attributes to accerlate SDP creation later. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        ret = ParseExtraAttributes( pOffer, &attribute );
    }

    return ret;
}

static SdpControllerResult_t serializeOrigin( SdpSerializerContext_t * pCtx,
                                              SdpControllerOrigin_t * pOrigin )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpOriginator_t origin;

    memset( &origin, 0, sizeof( SdpOriginator_t ) );
    origin.sessionId = pOrigin->sessionId;
    origin.sessionVersion = pOrigin->sessionVersion;
    origin.pUserName = pOrigin->pUserName;
    origin.userNameLength = pOrigin->userNameLength;
    origin.connectionInfo.networkType = SDP_NETWORK_IN;
    origin.connectionInfo.addressType = SDP_ADDRESS_IPV4;
    origin.connectionInfo.pAddress = pOrigin->sdpConnectionInformation.pConnectionAddress;
    origin.connectionInfo.addressLength = pOrigin->sdpConnectionInformation.connectionAddressLength;

    sdpResult = SdpSerializer_AddOriginator( pCtx, SDP_TYPE_ORIGINATOR, &origin );
    if( sdpResult != SDP_RESULT_OK )
    {
        LogError( ( "Serialize SDP origin failure, result: %d", sdpResult ) );
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
    }

    return ret;
}

static SdpControllerResult_t serializeTiming( SdpSerializerContext_t * pCtx,
                                              SdpControllerTiming_t * pTiming )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpTimeDescription_t time;

    memset( &time, 0, sizeof( SdpTimeDescription_t ) );
    time.startTime = pTiming->startTime;
    time.stopTime = pTiming->stopTime;

    sdpResult = SdpSerializer_AddTimeActive( pCtx, SDP_TYPE_TIME_ACTIVE, &time );
    if( sdpResult != SDP_RESULT_OK )
    {
        LogError( ( "Serialize SDP time active failure, result: %d", sdpResult ) );
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
    }

    return ret;
}

static SdpControllerResult_t serializeAttributes( SdpSerializerContext_t * pCtx,
                                                  SdpControllerAttributes_t * pAttributes,
                                                  uint16_t attributeCount )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpAttribute_t attribute;
    uint32_t i;
    SdpControllerAttributes_t * pCurrentAttrubute = pAttributes;

    for( i = 0; i < attributeCount; i++ )
    {
        attribute.pAttributeName = ( pCurrentAttrubute + i )->pAttributeName;
        attribute.attributeNameLength = ( pCurrentAttrubute + i )->attributeNameLength;
        attribute.pAttributeValue = ( pCurrentAttrubute + i )->pAttributeValue;
        attribute.attributeValueLength = ( pCurrentAttrubute + i )->attributeValueLength;

        sdpResult = SdpSerializer_AddAttribute( pCtx, SDP_TYPE_ATTRIBUTE, &attribute );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Serialize SDP attribute failure, result: %x, attribute name: %.*s, value: %.*s",
                        sdpResult,
                        ( attribute.attributeNameLength ), attribute.pAttributeName,
                        ( attribute.attributeValueLength ), attribute.pAttributeValue ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
        }
    }

    return ret;
}

static SdpControllerResult_t serializeConnectionInfo( SdpSerializerContext_t * pCtx,
                                                      SdpControllerConnectionInformation_t * pConnectionInfo )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpConnectionInfo_t connInfo;

    connInfo.networkType = SDP_NETWORK_IN;
    connInfo.addressType = SDP_ADDRESS_IPV4;
    connInfo.pAddress = pConnectionInfo->pConnectionAddress;
    connInfo.addressLength = pConnectionInfo->connectionAddressLength;

    sdpResult = SdpSerializer_AddConnectionInfo( pCtx, SDP_TYPE_CONNINFO, &connInfo );
    if( sdpResult != SDP_RESULT_OK )
    {
        LogError( ( "Serialize SDP connection information failure, result: %d", sdpResult ) );
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
    }

    return ret;
}

static SdpControllerResult_t serializeMedias( SdpSerializerContext_t * pCtx,
                                              SdpControllerMediaDescription_t * pMediaDescriptions,
                                              uint16_t mediaCount )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    uint32_t i;
    SdpControllerMediaDescription_t * pCurrentMedia = pMediaDescriptions;

    for( i = 0; i < mediaCount; i++ )
    {
        pCurrentMedia = pMediaDescriptions + i;

        /* Media name */
        sdpResult = SdpSerializer_AddBuffer( pCtx, SDP_TYPE_MEDIA, pCurrentMedia->pMediaName, pCurrentMedia->mediaNameLength );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Serialize SDP media name failure, result: %d", sdpResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
            break;
        }

        /* Media title */
        if( pCurrentMedia->pMediaTitle )
        {
            sdpResult = SdpSerializer_AddBuffer( pCtx, SDP_TYPE_MEDIA_TITLE, pCurrentMedia->pMediaTitle, pCurrentMedia->mediaTitleLength );
            if( sdpResult != SDP_RESULT_OK )
            {
                LogError( ( "Serialize SDP media title failure, result: %d", sdpResult ) );
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
                break;
            }
        }

        /* Media connection information */
        ret = serializeConnectionInfo( pCtx, &pCurrentMedia->connectionInformation );
        if( ret != SDP_CONTROLLER_RESULT_OK )
        {
            break;
        }

        /* Append media attributes. */
        ret = serializeAttributes( pCtx, &pCurrentMedia->attributes[ 0 ], pCurrentMedia->mediaAttributesCount );
        if( ret != SDP_CONTROLLER_RESULT_OK )
        {
            break;
        }
    }

    return ret;
}

static SdpControllerResult_t serializeSdpMessage( SdpControllerSdpDescription_t * pSdpDescription,
                                                  char * pOutputBuffer,
                                                  size_t * pOutputBufferSize )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    SdpSerializerContext_t ctx;
    const char * pBuffer;

    sdpResult = SdpSerializer_Init( &ctx, pOutputBuffer, *pOutputBufferSize );
    if( sdpResult != SDP_RESULT_OK )
    {
        LogError( ( "Init SDP serializer failure, result: %d", sdpResult ) );
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_INIT;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append version. */
        sdpResult = SdpSerializer_AddU64( &ctx, SDP_TYPE_VERSION, pSdpDescription->version );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Serialize SDP version failure, result: %d", sdpResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append origin. */
        ret = serializeOrigin( &ctx, &pSdpDescription->origin );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append session name. */
        sdpResult = SdpSerializer_AddBuffer( &ctx, SDP_TYPE_SESSION_NAME, pSdpDescription->pSessionName, pSdpDescription->sessionNameLength );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Serialize SDP session name failure, result: %d", sdpResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append timing description. */
        ret = serializeTiming( &ctx, &pSdpDescription->timingDescription );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append session attributes. */
        ret = serializeAttributes( &ctx, &pSdpDescription->attributes[ 0 ], pSdpDescription->sessionAttributesCount );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Append media information. */
        ret = serializeMedias( &ctx, &pSdpDescription->mediaDescriptions[ 0 ], pSdpDescription->mediaCount );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        sdpResult = SdpSerializer_Finalize( &ctx, &pBuffer, pOutputBufferSize );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Serialize SDP finalize failure, result: %d", sdpResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SERIALIZER_ADD;
        }
    }

    return ret;
}

static SdpControllerResult_t PopulateTransceiverSsrc( char ** ppBuffer,
                                                      size_t * pBufferLength,
                                                      SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                      const Transceiver_t * pTransceiver,
                                                      const char * pCname,
                                                      size_t cnameLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    if( ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pSdpLocalDescription == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pCname == NULL ) )
    {
        LogError( ( "Invalid input, ppBuffer: %p, pBufferLength: %p, pSdpLocalDescription: %p, pTransceiver: %p, pCname: %p",
                    ppBuffer,
                    pBufferLength,
                    pSdpLocalDescription,
                    pTransceiver,
                    pCname ) );
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    /* CNAME */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Initialize current buffer pointer/size and the pointer to the attribute count. */
        pCurBuffer = *ppBuffer;
        remainSize = *pBufferLength;
        pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu cname:%.*s",
                            pTransceiver->ssrc,
                            ( int ) cnameLength, pCname );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for SSRC CNAME" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* msid */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu msid:%.*s %.*s",
                            pTransceiver->ssrc,
                            ( int ) pTransceiver->streamIdLength, pTransceiver->streamId,
                            ( int ) pTransceiver->trackIdLength, pTransceiver->trackId );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for SSRC msid" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* mslabel */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu mslabel:%.*s",
                            pTransceiver->ssrc,
                            ( int ) pTransceiver->streamIdLength, pTransceiver->streamId );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for SSRC mslabel" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* label */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SSRC_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu label:%.*s",
                            pTransceiver->ssrc,
                            ( int ) pTransceiver->trackIdLength, pTransceiver->trackId );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for SSRC label" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateRtcpFb( char ** ppBuffer,
                                             size_t * pBufferLength,
                                             SdpControllerSdpDescription_t * pSdpLocalDescription,
                                             uint32_t codec,
                                             uint16_t twccId )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    if( ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pSdpLocalDescription == NULL ) )
    {
        LogError( ( "Invalid input, ppBuffer: %p, pBufferLength: %p, pSdpLocalDescription: %p",
                    ppBuffer,
                    pBufferLength,
                    pSdpLocalDescription ) );
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pCurBuffer = *ppBuffer;
        remainSize = *pBufferLength;
        pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu %s",
                            codec,
                            SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_GOOG_REMB );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for rtcp-fb H264 value" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* Append "rtcp-fb: ${codec} transport-cc" only if twccId is valid. */
    if( ( ret == SDP_CONTROLLER_RESULT_OK ) && ( twccId > 0 ) )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu %s",
                            codec,
                            SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_TRANSPORT_CC );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for rtcp-fb transport-cc" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesH264Profile42E01FLevelAsymmetryAllowedPacketization( char ** ppBuffer,
                                                                                                         size_t * pBufferLength,
                                                                                                         SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                                                                         SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                                                                         const Transceiver_t * pTransceiver,
                                                                                                         uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    uint8_t isOffer = pSdpRemoteDescription ? 0 : 1;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    const SdpControllerAttributes_t * pSourceAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H264 );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap H264 value" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    /* rtcp-fb: ${codec} nack pli */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu %s",
                            codec,
                            SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H264 );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for rtcp-fb H264 value" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* fmtp */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( !isOffer )
        {
            /* If creating SDP answer, try find fmtp from the remote description. */
            pSourceAttribute = FindFmtpBasedOnCodec( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes,
                                                     pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount,
                                                     codec );
        }

        /* Set fmtp only if:
         *   1. It's offer, or
         *   2. It's not offer but we found the corresponding fmtp from remote description. */
        if( isOffer || pSourceAttribute )
        {
            pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
            pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP;
            pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH;

            if( isOffer )
            {
                written = snprintf( pCurBuffer, remainSize, "%lu %s",
                                    codec,
                                    SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION );
            }
            else
            {
                written = snprintf( pCurBuffer, remainSize, "%.*s",
                                    ( int ) pSourceAttribute->attributeValueLength, pSourceAttribute->pAttributeValue );
            }

            if( written < 0 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
                LogError( ( "snprintf return unexpected value %d", written ) );
            }
            else if( written == remainSize )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
                LogError( ( "buffer has no space for fmtp" ) );
            }
            else
            {
                pTargetAttribute->pAttributeValue = pCurBuffer;
                pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
                *pTargetAttributeCount += 1;

                pCurBuffer += written;
                remainSize -= written;
            }
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesOpus( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    uint8_t isOffer = pSdpRemoteDescription ? 0 : 1;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    const SdpControllerAttributes_t * pSourceAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_OPUS );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap OPUS" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    /* fmtp */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( !isOffer )
        {
            /* If creating SDP answer, try find fmtp from the remote description. */
            pSourceAttribute = FindFmtpBasedOnCodec( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes,
                                                     pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount,
                                                     codec );
        }

        /* Set fmtp only if:
         *   1. It's offer, or
         *   2. It's not offer but we found the corresponding fmtp from remote description. */
        if( isOffer || pSourceAttribute )
        {
            pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
            pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP;
            pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH;

            if( isOffer )
            {
                written = snprintf( pCurBuffer, remainSize, "%lu %s",
                                    codec,
                                    SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_OPUS );
            }
            else
            {
                written = snprintf( pCurBuffer, remainSize, "%lu %.*s",
                                    codec,
                                    ( int ) pSourceAttribute->attributeValueLength, pSourceAttribute->pAttributeValue );
            }

            if( written < 0 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
                LogError( ( "snprintf return unexpected value %d", written ) );
            }
            else if( written == remainSize )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
                LogError( ( "buffer has no space for fmtp" ) );
            }
            else
            {
                pTargetAttribute->pAttributeValue = pCurBuffer;
                pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
                *pTargetAttributeCount += 1;

                pCurBuffer += written;
                remainSize -= written;
            }
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesVp8( char ** ppBuffer,
                                                         size_t * pBufferLength,
                                                         SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                         SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                         const Transceiver_t * pTransceiver,
                                                         uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_VP8 );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap VP8" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesMulaw( char ** ppBuffer,
                                                           size_t * pBufferLength,
                                                           SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                           SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                           const Transceiver_t * pTransceiver,
                                                           uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_MULAW );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap MULAW" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesAlaw( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_ALAW );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap ALAW" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributesH265( char ** ppBuffer,
                                                          size_t * pBufferLength,
                                                          SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                          SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                          const Transceiver_t * pTransceiver,
                                                          uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    uint8_t isOffer = pSdpRemoteDescription ? 0 : 1;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    const SdpControllerAttributes_t * pSourceAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;

    pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    pCurBuffer = *ppBuffer;
    remainSize = *pBufferLength;

    /* rtpmap */
    pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
    pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP;
    pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH;

    written = snprintf( pCurBuffer, remainSize, "%lu %s",
                        codec,
                        SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTPMAP_H265 );
    if( written < 0 )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        LogError( ( "snprintf return unexpected value %d", written ) );
    }
    else if( written == remainSize )
    {
        ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
        LogError( ( "buffer has no space for rtpmap H265 value" ) );
    }
    else
    {
        pTargetAttribute->pAttributeValue = pCurBuffer;
        pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
        *pTargetAttributeCount += 1;

        pCurBuffer += written;
        remainSize -= written;
    }

    /* rtcp-fb */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_FB_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%lu %s",
                            codec,
                            SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_FB_H265 );
        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for rtcp-fb H265 value" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* fmtp */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( !isOffer )
        {
            /* If creating SDP answer, try find fmtp from the remote description. */
            pSourceAttribute = FindFmtpBasedOnCodec( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes,
                                                     pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount,
                                                     codec );
        }

        /* Set fmtp only if:
         *   1. It's offer, or
         *   2. It's not offer but we found the corresponding fmtp from remote description. */
        if( isOffer || pSourceAttribute )
        {
            pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
            pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP;
            pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH;

            if( isOffer )
            {
                written = snprintf( pCurBuffer, remainSize, "%lu %s",
                                    codec,
                                    SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_FMTP_H265 );
            }
            else
            {
                written = snprintf( pCurBuffer, remainSize, "%lu %.*s",
                                    codec,
                                    ( int ) pSourceAttribute->attributeValueLength, pSourceAttribute->pAttributeValue );
            }

            if( written < 0 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
                LogError( ( "snprintf return unexpected value %d", written ) );
            }
            else if( written == remainSize )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
                LogError( ( "buffer has no space for fmtp" ) );
            }
            else
            {
                pTargetAttribute->pAttributeValue = pCurBuffer;
                pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
                *pTargetAttributeCount += 1;

                pCurBuffer += written;
                remainSize -= written;
            }
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return ret;
}

static SdpControllerResult_t PopulateCodecAttributes( char ** ppBuffer,
                                                      size_t * pBufferLength,
                                                      SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                      SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                      const Transceiver_t * pTransceiver,
                                                      uint32_t codec )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;

    if( ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pSdpLocalDescription == NULL ) ||
        ( pTransceiver == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
        LogError( ( "Invalid input, ppBuffer: %p, pBufferLength: %p, pSdpLocalDescription: %p, pTransceiver: %p",
                    ppBuffer,
                    pBufferLength,
                    pSdpLocalDescription,
                    pTransceiver ) );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ) )
        {
            ret = PopulateCodecAttributesH264Profile42E01FLevelAsymmetryAllowedPacketization( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT ) )
        {
            ret = PopulateCodecAttributesOpus( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT ) )
        {
            ret = PopulateCodecAttributesVp8( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT ) )
        {
            ret = PopulateCodecAttributesMulaw( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT ) )
        {
            ret = PopulateCodecAttributesAlaw( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else if( TRANSCEIVER_IS_CODEC_ENABLED( pTransceiver->codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT ) )
        {
            ret = PopulateCodecAttributesH265( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
        }
        else
        {
            /* TODO: Unknown, no matching codec. */
            LogError( ( "Codec is not supported, codec bit map: %x", ( int ) pTransceiver->codecBitMap ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_CODEC_NOT_SUPPORT;
        }
    }

    /* rtcp-fb: ${codec} goog-remb
     * rtcp-fb: ${codec} transport-cc */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        uint16_t twccId = 0;

        if( pSdpRemoteDescription && ( pSdpRemoteDescription->quickAccess.twccExtId > 0 ) )
        {
            twccId = pSdpRemoteDescription->quickAccess.twccExtId;
        }
        ret = PopulateRtcpFb( ppBuffer, pBufferLength, pSdpLocalDescription, codec, twccId );
    }

    return ret;
}

static const SdpControllerAttributes_t * FindAttributeName( const SdpControllerAttributes_t * pAttributes,
                                                            size_t attributeCount,
                                                            char * pPattern,
                                                            size_t patternLength )
{
    const SdpControllerAttributes_t * pRet = NULL;
    int i;

    if( ( pAttributes == NULL ) ||
        ( pPattern == NULL ) )
    {
        LogError( ( "Invalid input, pAttributes: %p, pPattern: %p", pAttributes, pPattern ) );
    }
    else
    {
        for( i = 0; i < attributeCount; i++ )
        {
            if( ( pAttributes[i].attributeNameLength == patternLength ) && ( strncmp( pAttributes[i].pAttributeName, pPattern, patternLength ) == 0 ) )
            {
                pRet = &pAttributes[i];
                break;
            }
        }
    }

    return pRet;
}

static const SdpControllerAttributes_t * FindFmtpBasedOnCodec( const SdpControllerAttributes_t * pAttributes,
                                                               size_t attributeCount,
                                                               uint32_t codec )
{
    const SdpControllerAttributes_t * pRet = NULL;
    char codecString[ TRANSCEIVER_CODEC_STRING_MAX_LENGTH + 1 ];
    int i, written;

    if( pAttributes == NULL )
    {
        LogError( ( "Invalid input, pAttributes: %p", pAttributes ) );
    }
    else
    {
        written = snprintf( codecString, TRANSCEIVER_CODEC_STRING_MAX_LENGTH + 1, "%lu", codec );
        if( written < 0 )
        {
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == TRANSCEIVER_CODEC_STRING_MAX_LENGTH + 1 )
        {
            LogError( ( "buffer has no space for codec string" ) );
        }
        else
        {
            for( i = 0; i < attributeCount; i++ )
            {
                if( ( pAttributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) &&
                    ( strncmp( pAttributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) == 0 ) &&
                    ( pAttributes[i].attributeValueLength >= written ) &&
                    ( strncmp( pAttributes[i].pAttributeValue, codecString, written ) == 0 ) )
                {
                    pRet = &pAttributes[i];
                    break;
                }
            }
        }
    }

    return pRet;
}

static SdpControllerResult_t PopulateSingleMedia( char ** ppBuffer,
                                                  size_t * pBufferLength,
                                                  SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                  SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                  const Transceiver_t * pTransceiver,
                                                  PeerConnectionContext_t * pPeerConnectionContext,
                                                  uint32_t codec,
                                                  const char * pLocalFingerprint,
                                                  size_t localFingerprintLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    uint8_t isOffer = 0;
    int written = 0;
    char * pCurBuffer = NULL;
    size_t remainSize = 0;
    SdpControllerAttributes_t * pTargetAttribute = NULL;
    const SdpControllerAttributes_t * pSourceAttribute = NULL;
    uint8_t * pTargetAttributeCount = NULL;
    PeerConnectionResult_t peerConnectionResult;
    PeerConnectionUserInfo_t localUserInfo;
    int i;

    if( ( ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pSdpLocalDescription == NULL ) ||
        ( pTransceiver == NULL ) ||
        ( pPeerConnectionContext == NULL ) )
    {
        LogError( ( "Invalid input, ppBuffer: %p, pBufferLength: %p, pSdpLocalDescription: %p, pTransceiver: %p, pPeerConnectionContext: %p",
                    ppBuffer,
                    pBufferLength,
                    pSdpLocalDescription,
                    pTransceiver,
                    pPeerConnectionContext ) );
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( pSdpRemoteDescription == NULL )
        {
            /* If no remote description, it's preparing SDP offer. */
            isOffer = 1;
        }

        /* Initialize current buffer pointer/size. */
        pCurBuffer = *ppBuffer;
        remainSize = *pBufferLength;
        pTargetAttributeCount = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount;
    }

    /* Set media name. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* We support only one payload type, so only one payload type printed in media name. */
        if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
        {
            written = snprintf( pCurBuffer, remainSize, "video 9 UDP/TLS/RTP/SAVPF %lu", codec );
        }
        else
        {
            written = snprintf( pCurBuffer, remainSize, "audio 9 UDP/TLS/RTP/SAVPF %lu", codec );
        }

        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for media name" ) );
        }
        else
        {
            pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].pMediaName = pCurBuffer;
            pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaNameLength = strlen( pCurBuffer );

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* Set media title and connection information. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].pMediaTitle = NULL;
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaTitleLength = 0;
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.pNetworkType = SDP_CONTROLLER_ORIGIN_DEFAULT_NET_TYPE;
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.networkTypeLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_NET_TYPE );
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.pAddressType = SDP_CONTROLLER_ORIGIN_IPV4_TYPE;
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.addressTypeLength = strlen( SDP_CONTROLLER_ORIGIN_IPV4_TYPE );
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.pConnectionAddress = SDP_CONTROLLER_ORIGIN_DEFAULT_IP_ADDRESS;
        pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].connectionInformation.connectionAddressLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_IP_ADDRESS );
    }

    /* msid */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MSID;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MSID_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "%.*s %.*s",
                            ( int ) pTransceiver->streamIdLength, pTransceiver->streamId,
                            ( int ) pTransceiver->trackIdLength, pTransceiver->trackId );

        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for msid" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* Query userinfo for later use. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        peerConnectionResult = PeerConnection_GetLocalUserInfo( pPeerConnectionContext, &localUserInfo );
        if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
        {
            LogError( ( "Fail to get local user info, return: %d", peerConnectionResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_GET_LOCALUSERINFO;
        }
    }

    /* ssrc */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        ret = PopulateTransceiverSsrc( &pCurBuffer, &remainSize, pSdpLocalDescription, pTransceiver, localUserInfo.pCname, localUserInfo.cnameLength );
    }

    /* rtcp, ice-ufrag, ice-pwd */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_LENGTH;
        pTargetAttribute->pAttributeValue = SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP;
        pTargetAttribute->attributeValueLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_RTCP_LENGTH;
        *pTargetAttributeCount += 1;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_UFRAG_LENGTH;
        pTargetAttribute->pAttributeValue = localUserInfo.pUserName;
        pTargetAttribute->attributeValueLength = localUserInfo.userNameLength;
        *pTargetAttributeCount += 1;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_PWD_LENGTH;
        pTargetAttribute->pAttributeValue = localUserInfo.pPassword;
        pTargetAttribute->attributeValueLength = localUserInfo.passwordLength;
        *pTargetAttributeCount += 1;
    }

    /* TODO: configable ice trickle. */
    /* ice-options:trickle */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_ICE_OPTION_LENGTH;
        pTargetAttribute->pAttributeValue = SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION;
        pTargetAttribute->attributeValueLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_VALUE_ICE_OPTION_LENGTH;
        *pTargetAttributeCount += 1;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FINGERPRINT_LENGTH;

        written = snprintf( pCurBuffer, remainSize, "sha-256 %.*s",
                            ( int ) localFingerprintLength, pLocalFingerprint );

        if( written < 0 )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
            LogError( ( "buffer has no space for msid" ) );
        }
        else
        {
            pTargetAttribute->pAttributeValue = pCurBuffer;
            pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
            *pTargetAttributeCount += 1;

            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* setup. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SETUP_LENGTH;

        if( isOffer )
        {
            pTargetAttribute->pAttributeValue = SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTPASS;
            pTargetAttribute->attributeValueLength = SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTPASS_LENGTH;
        }
        else
        {
            pTargetAttribute->pAttributeValue = SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE;
            pTargetAttribute->attributeValueLength = SDP_CONTROLLER_MEDIA_DTLS_ROLE_ACTIVE_LENGTH;
        }

        *pTargetAttributeCount += 1;
    }

    /* mid */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pSourceAttribute = FindAttributeName( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes,
                                              pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount,
                                              SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID,
                                              SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID_LENGTH );
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_MID_LENGTH;

        if( isOffer && pSourceAttribute )
        {
            pTargetAttribute->pAttributeValue = pSourceAttribute->pAttributeValue;
            pTargetAttribute->attributeValueLength = pSourceAttribute->attributeValueLength;
            *pTargetAttributeCount += 1;
        }
        else
        {
            written = snprintf( pCurBuffer, remainSize, "%u",
                                pSdpLocalDescription->mediaCount );

            if( written < 0 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
                LogError( ( "snprintf return unexpected value %d", written ) );
            }
            else if( written == remainSize )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_POPULATE_BUFFER_TOO_SMALL;
                LogError( ( "buffer has no space for mid" ) );
            }
            else
            {
                pTargetAttribute->pAttributeValue = pCurBuffer;
                pTargetAttribute->attributeValueLength = strlen( pCurBuffer );
                *pTargetAttributeCount += 1;

                pCurBuffer += written;
                remainSize -= written;
            }
        }
    }

    /* send/recv */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        TransceiverDirection_t targetDirection = TRANSCEIVER_TRACK_DIRECTION_UNKNOWN;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeValue = NULL;
        pTargetAttribute->attributeValueLength = 0;

        /* Find target direction. */
        if( isOffer )
        {
            targetDirection = pTransceiver->direction;
        }
        else
        {
            // in case of a missing m-line, we respond with the same m-line but direction set to inactive
            if( pTransceiver->direction == TRANSCEIVER_TRACK_DIRECTION_INACTIVE )
            {
                targetDirection = TRANSCEIVER_TRACK_DIRECTION_INACTIVE;
            }
            else
            {
                for( i = 0; i < pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].mediaAttributesCount; i++ )
                {
                    if( ( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV_LENGTH ) &&
                        ( strncmp( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV_LENGTH ) == 0 ) )
                    {
                        targetDirection = TRANSCEIVER_TRACK_DIRECTION_SENDRECV;
                        break;
                    }
                    else if( ( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY_LENGTH ) &&
                             ( strncmp( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY_LENGTH ) == 0 ) )
                    {
                        targetDirection = TRANSCEIVER_TRACK_DIRECTION_SENDONLY;
                        break;
                    }
                    else if( ( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY_LENGTH ) &&
                             ( strncmp( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY_LENGTH ) == 0 ) )
                    {
                        targetDirection = TRANSCEIVER_TRACK_DIRECTION_RECVONLY;
                        break;
                    }
                    else if( ( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE_LENGTH ) &&
                             ( strncmp( pSdpRemoteDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE_LENGTH ) == 0 ) )
                    {
                        targetDirection = TRANSCEIVER_TRACK_DIRECTION_INACTIVE;
                        break;
                    }
                }
            }
        }

        switch( targetDirection )
        {
            case TRANSCEIVER_TRACK_DIRECTION_SENDRECV:
                pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV;
                pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDRECV_LENGTH;
                break;
            case TRANSCEIVER_TRACK_DIRECTION_SENDONLY:
                pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY;
                pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_SENDONLY_LENGTH;
                break;
            case TRANSCEIVER_TRACK_DIRECTION_RECVONLY:
                pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY;
                pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RECVONLY_LENGTH;
                break;
            case TRANSCEIVER_TRACK_DIRECTION_INACTIVE:
            default:
                // https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiverdirection
                LogWarn( ( "Incorrect/no transceiver direction set...this attribute will be set to inactive, target: %d", targetDirection ) );
                pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE;
                pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_INACTIVE_LENGTH;
        }

        *pTargetAttributeCount += 1;
    }

    /* rtcp-mux, rtcp-rsize */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_MUX;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_MUX_LENGTH;
        pTargetAttribute->pAttributeValue = NULL;
        pTargetAttribute->attributeValueLength = 0;

        *pTargetAttributeCount += 1;

        pTargetAttribute = &pSdpLocalDescription->mediaDescriptions[ pSdpLocalDescription->mediaCount ].attributes[ *pTargetAttributeCount ];
        pTargetAttribute->pAttributeName = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_RSIZE;
        pTargetAttribute->attributeNameLength = SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTCP_RSIZE_LENGTH;
        pTargetAttribute->pAttributeValue = NULL;
        pTargetAttribute->attributeValueLength = 0;

        *pTargetAttributeCount += 1;
    }

    /* Popupate codec relevant attributes. */
    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        ret = PopulateCodecAttributes( &pCurBuffer, &remainSize, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, codec );
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
        pSdpLocalDescription->mediaCount++;
    }

    return ret;
}

static SdpControllerAttributes_t * FindH264FmtpAttribute( SdpControllerAttributes_t * pAttributes,
                                                          uint8_t attributeCount,
                                                          SdpControllerAttributes_t * pTargetRtpmapAttribute )
{
    const char * pCodecStart = NULL;
    size_t codecStringLength = 0;
    int i;
    SdpControllerAttributes_t * pTargetFmtpAttribute = NULL;

    if( pAttributes && pTargetRtpmapAttribute )
    {
        /* Find the corresponding codec payload from target RTPMAP attribute. */
        pCodecStart = pTargetRtpmapAttribute->pAttributeValue;
        while( pCodecStart && codecStringLength < pTargetRtpmapAttribute->attributeValueLength )
        {
            if( ( pCodecStart[ codecStringLength ] >= '0' ) && ( pCodecStart[ codecStringLength ] <= '9' ) )
            {
                codecStringLength++;
            }
            else
            {
                break;
            }
        }

        /* Find corresonding fmtp attribute. */
        if( codecStringLength )
        {
            for( i = 0; i < attributeCount; i++ )
            {
                if( ( pAttributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) &&
                    ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP, pAttributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) == 0 ) &&
                    ( pAttributes[i].attributeValueLength >= codecStringLength ) &&
                    ( strncmp( pCodecStart, pAttributes[i].pAttributeValue, codecStringLength ) == 0 ) )
                {
                    /* Found the fmtp. */
                    pTargetFmtpAttribute = &pAttributes[i];
                }
            }
        }
    }

    return pTargetFmtpAttribute;
}

static uint32_t CalculateH264ScoreByFmtp( SdpControllerAttributes_t * pTargetFmtpAttribute )
{
    uint32_t score = 0;
    const char * pProfileLevelIdStart = NULL;
    uint32_t profileLevelId = 0;
    StringUtilsResult_t stringResult;
    size_t remainLength = 0;

    do
    {
        if( !pTargetFmtpAttribute )
        {
            /* No target fmtp found, return 0. */
            break;
        }

        /* Calculate the score from fmtp. */
        if( StringUtils_StrStr( pTargetFmtpAttribute->pAttributeValue, pTargetFmtpAttribute->attributeValueLength,
                                SDP_CONTROLLER_H264_PACKETIZATION_MODE, SDP_CONTROLLER_H264_PACKETIZATION_MODE_LENGTH ) )
        {
            /* Packetization mode is mandatory. */
            score += SDP_CONTROLLER_H264_FMTP_MINIMUM_SCORE;
        }

        if( StringUtils_StrStr( pTargetFmtpAttribute->pAttributeValue, pTargetFmtpAttribute->attributeValueLength,
                                SDP_CONTROLLER_H264_ASYMMETRY_ALLOWED, SDP_CONTROLLER_H264_ASYMMETRY_ALLOWED_LENGTH ) )
        {
            score++;
        }

        pProfileLevelIdStart = StringUtils_StrStr( pTargetFmtpAttribute->pAttributeValue, pTargetFmtpAttribute->attributeValueLength,
                                                   SDP_CONTROLLER_H264_PROFILE_LEVEL_ID, SDP_CONTROLLER_H264_PROFILE_LEVEL_ID_LENGTH );
        if( !pProfileLevelIdStart )
        {
            break;
        }

        /* Move pProfileLevelIdStart to the start of ID. */
        pProfileLevelIdStart = pProfileLevelIdStart + SDP_CONTROLLER_H264_PROFILE_LEVEL_ID_LENGTH;
        remainLength = pTargetFmtpAttribute->pAttributeValue + pTargetFmtpAttribute->attributeValueLength - pProfileLevelIdStart;
        stringResult = StringUtils_ConvertStringToHex( pProfileLevelIdStart, remainLength, &profileLevelId );
        if( stringResult != STRING_UTILS_RESULT_OK )
        {
            LogWarn( ( "Fail to convert string(%d): %.*s to hex.",
                       remainLength,
                       ( int ) remainLength, pProfileLevelIdStart ) );
            break;
        }

        if( ( ( profileLevelId & SDP_CONTROLLER_H264_FMTP_SUBPROFILE_MASK ) == ( SDP_CONTROLLER_H264_PROFILE_42E01F & SDP_CONTROLLER_H264_FMTP_SUBPROFILE_MASK ) ) &&
            ( ( profileLevelId & SDP_CONTROLLER_H264_FMTP_PROFILE_LEVEL_MASK ) <= ( SDP_CONTROLLER_H264_PROFILE_42E01F & SDP_CONTROLLER_H264_FMTP_PROFILE_LEVEL_MASK ) ) )
        {
            score++;
        }
    } while( 0 );

    return score;
}

static uint32_t CollectAttributesCodecBitMap( SdpControllerAttributes_t * pAttributes,
                                              uint8_t attributeCount,
                                              uint32_t * pCodecPayloads,
                                              size_t codecPayloadsSize,
                                              uint32_t * pRtxCodecPayloads,
                                              size_t * pRtxCodecPayloadsSize )
{
    uint32_t codecBitMap = 0, h264Score = 0, highestH264Score = 0;
    int i;
    StringUtilsResult_t stringResult;
    SdpControllerAttributes_t * pH264FmtpAttribute = NULL;
    uint32_t rtxPayloadNextIndex = 0;
    const char * pAtp = NULL;
    size_t stringLength;
    uint32_t rtxPayload;
    uint32_t aptPayload;

    if( ( pAttributes == NULL ) ||
        ( pCodecPayloads == NULL ) ||
        ( codecPayloadsSize < TRANSCEIVER_RTC_CODEC_NUM ) ||
        ( pRtxCodecPayloads == NULL ) )
    {
        LogError( ( "Invalid input, pAttributes: %p, pCodecPayloads: %p, pRtxCodecPayloads: %p, codecPayloadsSize: %u",
                    pAttributes,
                    pCodecPayloads,
                    pRtxCodecPayloads,
                    codecPayloadsSize ) );
    }
    else
    {
        for( i = 0; i < attributeCount; i++ )
        {
            if( ( pAttributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH ) &&
                ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP, pAttributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_RTPMAP_LENGTH ) == 0 ) )
            {
                if( ( highestH264Score < SDP_CONTROLLER_H264_FMTP_HIGHEST_SCORE ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH ) &&
                    ( strncmp( SDP_CONTROLLER_CODEC_H264_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH, SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH ) == 0 ) )
                {
                    pH264FmtpAttribute = FindH264FmtpAttribute( pAttributes, attributeCount, &pAttributes[i] );
                    h264Score = CalculateH264ScoreByFmtp( pH264FmtpAttribute );
                    if( ( h264Score >= SDP_CONTROLLER_H264_FMTP_MINIMUM_SCORE ) && ( highestH264Score < h264Score ) )
                    {
                        stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ] );
                        if( stringResult != STRING_UTILS_RESULT_OK )
                        {
                            LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                       stringResult,
                                       ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H264_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                       pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ] ) );
                        }
                        else
                        {
                            TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT );
                            LogDebug( ( "Found H264 codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ] ) );
                            highestH264Score = h264Score;
                        }
                    }
                }
                else if( !TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_VP8_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH, SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH ) == 0 ) )
                {
                    stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_VP8_BIT ] );
                    if( stringResult != STRING_UTILS_RESULT_OK )
                    {
                        LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                   stringResult,
                                   ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_VP8_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                   pCodecPayloads[ TRANSCEIVER_RTC_CODEC_VP8_BIT ] ) );
                    }
                    else
                    {
                        TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT );
                        LogDebug( ( "Found VP8 codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_VP8_BIT ] ) );
                    }
                }
                else if( !TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_H265_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH, SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH ) == 0 ) )
                {
                    stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H265_BIT ] );
                    if( stringResult != STRING_UTILS_RESULT_OK )
                    {
                        LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                   stringResult,
                                   ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_H265_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                   pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H265_BIT ] ) );
                    }
                    else
                    {
                        TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT );
                        LogDebug( ( "Found H265 codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_H265_BIT ] ) );
                    }
                }
                else if( !TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_OPUS_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH, SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH ) == 0 ) )
                {
                    stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_OPUS_BIT ] );
                    if( stringResult != STRING_UTILS_RESULT_OK )
                    {
                        LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                   stringResult,
                                   ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_OPUS_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                   pCodecPayloads[ TRANSCEIVER_RTC_CODEC_OPUS_BIT ] ) );
                    }
                    else
                    {
                        TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT );
                        LogDebug( ( "Found OPUS codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_OPUS_BIT ] ) );
                    }
                }
                else if( !TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_MULAW_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH, SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH ) == 0 ) )
                {
                    stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ] );
                    if( stringResult != STRING_UTILS_RESULT_OK )
                    {
                        LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                   stringResult,
                                   ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_MULAW_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                   pCodecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ] ) );
                    }
                    else
                    {
                        TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT );
                        LogDebug( ( "Found MULAW codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ] ) );
                    }
                }
                else if( !TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT ) && ( pAttributes[i].attributeValueLength >= SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_ALAW_VALUE, pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH, SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH ) == 0 ) )
                {
                    stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH, &pCodecPayloads[ TRANSCEIVER_RTC_CODEC_ALAW_BIT ] );
                    if( stringResult != STRING_UTILS_RESULT_OK )
                    {
                        LogWarn( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                   stringResult,
                                   ( int ) pAttributes[i].attributeValueLength - SDP_CONTROLLER_CODEC_ALAW_VALUE_LENGTH, pAttributes[i].pAttributeValue,
                                   pCodecPayloads[ TRANSCEIVER_RTC_CODEC_ALAW_BIT ] ) );
                    }
                    else
                    {
                        TRANSCEIVER_ENABLE_CODEC( codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT );
                        LogDebug( ( "Found ALAW codec: %lu", pCodecPayloads[ TRANSCEIVER_RTC_CODEC_ALAW_BIT ] ) );
                    }
                }
                else
                {
                    /* Do nothing if it's not known string. */
                }
            }
            else if( ( pAttributes[i].attributeNameLength == SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) &&
                     ( strncmp( SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP, pAttributes[i].pAttributeName, SDP_CONTROLLER_MEDIA_ATTRIBUTE_NAME_FMTP_LENGTH ) == 0 ) )
            {
                pAtp = StringUtils_StrStr( pAttributes[i].pAttributeValue, pAttributes[i].attributeValueLength, SDP_CONTROLLER_CODEC_APT_VALUE, SDP_CONTROLLER_CODEC_APT_VALUE_LENGTH );

                if( pAtp == NULL )
                {
                    /* It's not RTX FMTP message, ignore it. */
                    continue;
                }

                /* It's RTX fmtp in format "fmtp:${RTX_payload} apt=${RTC_payload}". */
                if( rtxPayloadNextIndex >= *pRtxCodecPayloadsSize )
                {
                    LogWarn( ( "No memory for RTX payloads, drop FMTP APT: %.*s",
                               ( int ) pAttributes[i].attributeValueLength,
                               pAttributes[i].pAttributeValue ) );
                    continue;
                }

                /* Parse RTX payload */
                stringResult = StringUtils_ConvertStringToUl( pAttributes[i].pAttributeValue,
                                                              pAttributes[i].attributeValueLength, &rtxPayload );
                if( stringResult != STRING_UTILS_RESULT_OK )
                {
                    LogWarn( ( "StringUtils_ConvertStringToUl RTX payload fail, result %d, converting %.*s to %lu",
                               stringResult,
                               ( int ) pAttributes[i].attributeValueLength, pAttributes[i].pAttributeValue,
                               rtxPayload ) );
                    continue;
                }

                /* Parse APT payload */
                stringLength = pAttributes[i].pAttributeValue + pAttributes[i].attributeValueLength - pAtp - SDP_CONTROLLER_CODEC_APT_VALUE_LENGTH;
                stringResult = StringUtils_ConvertStringToUl( pAtp + SDP_CONTROLLER_CODEC_APT_VALUE_LENGTH,
                                                              stringLength, &aptPayload );
                if( stringResult != STRING_UTILS_RESULT_OK )
                {
                    LogWarn( ( "StringUtils_ConvertStringToUl APT payload fail, result %d, converting %.*s to %lu",
                               stringResult,
                               ( int ) pAttributes[i].attributeValueLength, pAttributes[i].pAttributeValue,
                               rtxPayload ) );
                    continue;
                }

                pRtxCodecPayloads[ rtxPayloadNextIndex++ ] = SDP_CONTROLLER_SET_PAYLOAD( rtxPayload, aptPayload );
                LogDebug( ( "Found RTX payload, rtxPayload: %lu, aptPayload: %lu",
                            rtxPayload,
                            aptPayload ) );
            }
            else
            {
                /* Empty else. */
            }
        }

        *pRtxCodecPayloadsSize = rtxPayloadNextIndex;
    }

    return codecBitMap;
}

static const Transceiver_t * OccupyProperTransceiver( SdpControllerMediaDescription_t * pRemoteMediaDescription,
                                                      const Transceiver_t * pTransceivers[],
                                                      size_t transceiversCount,
                                                      uint8_t * pIsTransceiverPopulated,
                                                      uint32_t * pChosenCodec )
{
    const Transceiver_t * pTransceiver = NULL;
    int currentTransceiverIdx = 0;
    TransceiverTrackKind_t trackKind;
    uint8_t skipProcess = 0;
    uint32_t mediaCodecBitMap = 0;
    uint32_t codecPayloads[ TRANSCEIVER_RTC_CODEC_NUM ];
    uint32_t rtxCodecPayloads[ SDP_CONTROLLER_MAX_FMTP_APT_NUM ];
    size_t rtxCodecPayloadsCount = SDP_CONTROLLER_MAX_FMTP_APT_NUM;
    int count = 0;
    int i,j;
    const char * pStart, * pEnd;
    size_t tokenLength, remainLength;

    if( ( pRemoteMediaDescription == NULL ) || ( pTransceivers == NULL ) || ( pIsTransceiverPopulated == NULL ) || ( pChosenCodec == NULL ) )
    {
        skipProcess = 1;
        LogError( ( "Invalid input, pRemoteMediaDescription: %p, pTransceivers: %p, pIsTransceiverPopulated: %p, pChosenCodec: %p",
                    pRemoteMediaDescription, pTransceivers, pIsTransceiverPopulated, pChosenCodec ) );
    }

    if( !skipProcess )
    {
        if( ( pRemoteMediaDescription->mediaNameLength >= 5 ) && ( strncmp( pRemoteMediaDescription->pMediaName, "video", 5 ) == 0 ) )
        {
            trackKind = TRANSCEIVER_TRACK_KIND_VIDEO;
            LogDebug( ( "Appending video tranceiver" ) );
        }
        else if( ( pRemoteMediaDescription->mediaNameLength >= 5 ) && ( strncmp( pRemoteMediaDescription->pMediaName, "audio", 5 ) == 0 ) )
        {
            trackKind = TRANSCEIVER_TRACK_KIND_AUDIO;
            LogDebug( ( "Appending audio tranceiver" ) );
        }
        else
        {
            /* Ignore unknown media type. */
            LogWarn( ( "Ignore unknown media type, media name: %.*s",
                       ( int ) pRemoteMediaDescription->mediaNameLength, pRemoteMediaDescription->pMediaName ) );
            skipProcess = 1;
        }
    }

    /* Search default MULAW & ALAW payload in media name. */
    if( !skipProcess )
    {
        memset( codecPayloads, 0, sizeof( codecPayloads ) );
        memset( rtxCodecPayloads, 0, sizeof( rtxCodecPayloads ) );

        pStart = pRemoteMediaDescription->pMediaName;
        remainLength = pRemoteMediaDescription->mediaNameLength;
        do {
            count++;
            pEnd = memchr( pStart, ' ', remainLength );

            if( pEnd )
            {
                tokenLength = pEnd - pStart;
            }
            else
            {
                tokenLength = remainLength;
            }

            /* Here is one media name example: "audio 9 UDP/TLS/RTP/SAVPF 111 63 103 104 9 0 8 106 105 13 110 112 113 126".
             * The beginning 3 tokens are not codec part, just ignore them here. */
            if( count > 3 )
            {
                if( ( tokenLength == SDP_CONTROLLER_CODEC_MULAW_DEFAULT_INDEX_LENGTH ) &&
                    ( strncmp( SDP_CONTROLLER_CODEC_MULAW_DEFAULT_INDEX, pStart, tokenLength ) == 0 ) )
                {
                    TRANSCEIVER_ENABLE_CODEC( mediaCodecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT );
                    codecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ] = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_MULAW;
                    break;
                }
                else if( ( tokenLength == SDP_CONTROLLER_CODEC_ALAW_DEFAULT_INDEX_LENGTH ) &&
                         ( strncmp( SDP_CONTROLLER_CODEC_ALAW_DEFAULT_INDEX, pStart, tokenLength ) == 0 ) )
                {
                    TRANSCEIVER_ENABLE_CODEC( mediaCodecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT );
                    codecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ] = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_ALAW;
                    break;
                }
                else
                {
                    /* Do nothing if it's neither MULAW nor ALAW. */
                }
            }

            if( pEnd )
            {
                pStart = pEnd + 1;
                remainLength = remainLength - tokenLength - 1; /* minus extra 1 for space. */
            }
        } while( pEnd != NULL );

        /* Find proper codec bit map by looking for rtpmap. */
        mediaCodecBitMap |= CollectAttributesCodecBitMap( pRemoteMediaDescription->attributes, pRemoteMediaDescription->mediaAttributesCount,
                                                          codecPayloads, TRANSCEIVER_RTC_CODEC_NUM,
                                                          rtxCodecPayloads, &rtxCodecPayloadsCount );
        LogDebug( ( "Scanned codec from remote media description, mediaCodecBitMap: %lx", mediaCodecBitMap ) );
    }

    if( !skipProcess )
    {
        /* Set RTX payloads into codecPayloads. */
        for( i = 0; i < rtxCodecPayloadsCount; i++ )
        {
            for( j = TRANSCEIVER_RTC_CODEC_MULAW_BIT; j < TRANSCEIVER_RTC_CODEC_NUM; j++ )
            {
                if( codecPayloads[ j ] == SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( rtxCodecPayloads[i] ) )
                {
                    codecPayloads[ j ] = rtxCodecPayloads[i];
                }
            }
        }
    }

    if( !skipProcess )
    {
        for( currentTransceiverIdx = 0; currentTransceiverIdx < transceiversCount; currentTransceiverIdx++ )
        {
            if( ( pIsTransceiverPopulated[currentTransceiverIdx] != 0 ) || ( pTransceivers[currentTransceiverIdx]->trackKind != trackKind ) ||
                ( ( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap ) == 0 ) )
            {
                LogDebug( ( "Skip transceiver index: %d, pIsTransceiverPopulated[%d]: %d, pTransceivers[%d].trackKind: %d, pTransceivers[%d].codecBitMap: %lx",
                            currentTransceiverIdx, currentTransceiverIdx, pIsTransceiverPopulated[currentTransceiverIdx], currentTransceiverIdx, pTransceivers[currentTransceiverIdx]->trackKind, currentTransceiverIdx, pTransceivers[currentTransceiverIdx]->codecBitMap ) );
                continue;
            }

            if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_VP8_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_H265_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_OPUS_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_MULAW_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else if( TRANSCEIVER_IS_CODEC_ENABLED( mediaCodecBitMap & pTransceivers[currentTransceiverIdx]->codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT ) )
            {
                *pChosenCodec = codecPayloads[ TRANSCEIVER_RTC_CODEC_ALAW_BIT ];
                pIsTransceiverPopulated[currentTransceiverIdx] = 1;
                pTransceiver = pTransceivers[currentTransceiverIdx];
                break;
            }
            else
            {
                /* Unexpected to enter this condition. */
            }
        }

        if( pTransceiver )
        {
            LogDebug( ( "Found transceiver, idx: %d, codec: %lu", currentTransceiverIdx, *pChosenCodec ) );
        }
        else
        {
            LogWarn( ( "Transceiver not found, mediaCodecBitMap: %lx", mediaCodecBitMap ) );
        }
    }

    return pTransceiver;
}

static uint32_t GetDefaultCodec( uint32_t codecBitMap )
{
    uint32_t codec = 0;

    if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_H264;
    }
    else if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_OPUS_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_OPUS;
    }
    else if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_VP8_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_VP8;
    }
    else if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_MULAW_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_MULAW;
    }
    else if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_ALAW_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_ALAW;
    }
    else if( TRANSCEIVER_IS_CODEC_ENABLED( codecBitMap, TRANSCEIVER_RTC_CODEC_H265_BIT ) )
    {
        codec = TRANSCEIVER_RTC_CODEC_DEFAULT_PAYLOAD_H265;
    }
    else
    {
        LogError( ( "No default codec found." ) );
    }

    return codec;
}

SdpControllerResult_t SdpController_DeserializeSdpOffer( const char * pSdpOfferContent,
                                                         size_t sdpOfferContentLength,
                                                         SdpControllerSdpDescription_t * pOffer )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    SdpResult_t sdpResult = SDP_RESULT_OK;
    StringUtilsResult_t stringResult;
    SdpDeserializerContext_t ctx;
    const char * pValue;
    size_t valueLength;
    uint8_t type;

    if( ( pSdpOfferContent == NULL ) || ( pOffer == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        memset( pOffer, 0, sizeof( SdpControllerSdpDescription_t ) );

        sdpResult = SdpDeserializer_Init( &ctx, pSdpOfferContent, sdpOfferContentLength );
        if( sdpResult != SDP_RESULT_OK )
        {
            LogError( ( "Init SDP deserializer failure, result: %d", sdpResult ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_DESERIALIZER_INIT;
        }
    }

    while( sdpResult == SDP_RESULT_OK )
    {
        sdpResult = SdpDeserializer_GetNext( &ctx, &type, &pValue, &valueLength );

        if( sdpResult != SDP_RESULT_OK )
        {
            break;
        }
        else if( type == SDP_TYPE_MEDIA )
        {
            pOffer->mediaDescriptions[ pOffer->mediaCount ].pMediaName = pValue;
            pOffer->mediaDescriptions[ pOffer->mediaCount ].mediaNameLength = valueLength;
            pOffer->mediaCount++;
        }
        else if( pOffer->mediaCount != 0 )
        {
            if( type == SDP_TYPE_ATTRIBUTE )
            {
                ret = parseMediaAttributes( pOffer, pValue, valueLength );
                if( ret != SDP_CONTROLLER_RESULT_OK )
                {
                    LogError( ( "parseMediaAttributes fail, result %d", ret ) );
                    break;
                }
            }
            else if( type == SDP_TYPE_SESSION_INFO )
            {
                // Media Title
                pOffer->mediaDescriptions[ pOffer->mediaCount - 1 ].pMediaTitle = pValue;
                pOffer->mediaDescriptions[ pOffer->mediaCount - 1 ].mediaTitleLength = valueLength;
            }
            else
            {
                /* Do nothing. */
            }
        }
        else
        {
            /* No media description before, these attributes belongs to session. */
            if( type == SDP_TYPE_SESSION_NAME )
            {
                // SDP Session Name
                pOffer->pSessionName = pValue;
                pOffer->sessionNameLength = valueLength;
            }
            else if( type == SDP_TYPE_SESSION_INFO )
            {
                // SDP Session Information
                pOffer->pSessionInformation = pValue;
                pOffer->sessionInformationLength = valueLength;
            }
            else if( type == SDP_TYPE_URI )
            {
                // SDP URI
                pOffer->pUri = pValue;
                pOffer->uriLength = valueLength;
            }
            else if( type == SDP_TYPE_EMAIL )
            {
                // SDP Email Address
                pOffer->pEmailAddress = pValue;
                pOffer->emailAddressLength = valueLength;
            }
            else if( type == SDP_TYPE_PHONE )
            {
                // SDP Phone number
                pOffer->pPhoneNumber = pValue;
                pOffer->phoneNumberLength = valueLength;
            }
            else if( type == SDP_TYPE_VERSION )
            {
                // Version
                stringResult = StringUtils_ConvertStringToUl( pValue, valueLength, &pOffer->version );
                if( stringResult != STRING_UTILS_RESULT_OK )
                {
                    LogError( ( "StringUtils_ConvertStringToUl fail, result %d, converting %.*s to %lu",
                                stringResult,
                                ( int ) valueLength, pValue,
                                pOffer->version ) );
                    ret = SDP_CONTROLLER_RESULT_SDP_INVALID_VERSION;
                    break;
                }
            }
            else if( type == SDP_TYPE_ATTRIBUTE )
            {
                ret = parseSessionAttributes( pOffer, pValue, valueLength );
                if( ret != SDP_CONTROLLER_RESULT_OK )
                {
                    LogError( ( "parseSessionAttributes fail, result %d", ret ) );
                    break;
                }
            }
            else
            {
                /* Do nothing. */
            }
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( pOffer->quickAccess.pFingerprint == NULL )
        {
            /* fingerprint is mandatory in the SDP. */
            LogError( ( "No fingerprint found in the SDP content." ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_NO_FINGERPRINT_FOUND;
        }
        else if( pOffer->quickAccess.pIceUfrag == NULL )
        {
            /* ice-ufrag is mandatory in the SDP. */
            LogError( ( "No ice-ufrag found in the SDP content." ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_NO_ICE_UFRAG_FOUND;
        }
        else if( pOffer->quickAccess.pIcePwd == NULL )
        {
            /* ice-pwd is mandatory in the SDP. */
            LogError( ( "No ice-pwd found in the SDP content." ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_NO_ICE_PWD_FOUND;
        }
        else
        {
            /* Everything is good. */
        }
    }

    return ret;
}

SdpControllerResult_t SdpController_GetSdpOfferContent( const char * pSdpMessage,
                                                        size_t sdpMessageLength,
                                                        const char ** ppSdpOfferContent,
                                                        size_t * pSdpOfferContentLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    JSONStatus_t jsonResult;
    size_t start = 0, next = 0;
    JSONPair_t pair = { 0 };
    uint8_t isContentFound = 0;

    if( ( pSdpMessage == NULL ) || ( ppSdpOfferContent == NULL ) || ( pSdpOfferContentLength == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        jsonResult = JSON_Validate( pSdpMessage, sdpMessageLength );

        if( jsonResult != JSONSuccess )
        {
            ret = SDP_CONTROLLER_RESULT_INVALID_JSON;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Check if it's SDP offer. */
        jsonResult = JSON_Iterate( pSdpMessage, sdpMessageLength, &start, &next, &pair );

        while( jsonResult == JSONSuccess )
        {
            if( ( strncmp( pair.key, SDP_CONTROLLER_SDP_OFFER_MESSAGE_TYPE_KEY, pair.keyLength ) == 0 ) &&
                ( strncmp( pair.value, SDP_CONTROLLER_SDP_OFFER_MESSAGE_TYPE_VALUE, pair.valueLength ) != 0 ) )
            {
                /* It's not expected SDP offer message. */
                LogWarn( ( "Message type \"%.*s\" is not SDP offer type\n",
                           ( int ) pair.valueLength, pair.value ) );
                ret = SDP_CONTROLLER_RESULT_NOT_SDP_OFFER;
            }
            else if( strncmp( pair.key, SDP_CONTROLLER_SDP_OFFER_MESSAGE_CONTENT_KEY, pair.keyLength ) == 0 )
            {
                *ppSdpOfferContent = pair.value;
                *pSdpOfferContentLength = pair.valueLength;
                isContentFound = 1;
                break;
            }
            else
            {
                /* Skip unknown attributes. */
            }

            jsonResult = JSON_Iterate( pSdpMessage, sdpMessageLength, &start, &next, &pair );
        }
    }

    if( ( ret == SDP_CONTROLLER_RESULT_OK ) && !isContentFound )
    {
        ret = SDP_CONTROLLER_RESULT_NOT_SDP_OFFER;
    }

    return ret;
}

SdpControllerResult_t SdpController_DeserializeSdpContentNewline( const char * pSdpContent,
                                                                  size_t sdpContentLength,
                                                                  char ** ppSdpConvertedContent,
                                                                  size_t * pSdpConvertedContentLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    const char * pCurSdp = pSdpContent, * pNext;
    char * pCurOutput = *ppSdpConvertedContent;
    size_t lineLength, outputLength = 0;

    if( ( pSdpContent == NULL ) || ( ppSdpConvertedContent == NULL ) || ( pSdpConvertedContentLength == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        while( ( pNext = strstr( pCurSdp, SDP_CONTROLLER_SDP_NEWLINE_ENDING ) ) != NULL )
        {
            lineLength = pNext - pCurSdp;

            if( ( lineLength >= 2 ) &&
                ( pCurSdp[ lineLength - 2 ] == '\\' ) && ( pCurSdp[ lineLength - 1 ] == 'r' ) )
            {
                lineLength -= 2;
            }

            if( *pSdpConvertedContentLength < outputLength + lineLength + 2 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_CONVERTED_BUFFER_TOO_SMALL;
                break;
            }

            memcpy( pCurOutput, pCurSdp, lineLength );
            pCurOutput += lineLength;
            *pCurOutput++ = '\r';
            *pCurOutput++ = '\n';
            outputLength += lineLength + 2;

            pCurSdp = pNext + 2;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *pSdpConvertedContentLength = outputLength;
    }

    return ret;
}

SdpControllerResult_t SdpController_SerializeSdpNewline( const char * pSdpContent,
                                                         size_t sdpContentLength,
                                                         char * pSdpConvertedContent,
                                                         size_t * pSdpConvertedContentLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    const char * pCurSdp = pSdpContent, * pNext, * pTail;
    char * pCurOutput = pSdpConvertedContent;
    size_t lineLength, outputLength = 0;
    int writtenLength;

    if( ( pSdpContent == NULL ) || ( pSdpConvertedContent == NULL ) || ( pSdpConvertedContentLength == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        pTail = pSdpContent + sdpContentLength;

        while( ( pNext = memchr( pCurSdp, '\n', pTail - pCurSdp ) ) != NULL )
        {
            lineLength = pNext - pCurSdp;

            if( ( lineLength > 0 ) &&
                ( pCurSdp[ lineLength - 1 ] == '\r' ) )
            {
                lineLength--;
            }
            else
            {
                /* do nothing, coverity happy. */
            }

            if( *pSdpConvertedContentLength < outputLength + lineLength + 4 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_CONVERTED_BUFFER_TOO_SMALL;
                break;
            }

            writtenLength = snprintf( pCurOutput, *pSdpConvertedContentLength - outputLength, "%.*s\\r\\n",
                                      ( int ) lineLength,
                                      pCurSdp );
            if( writtenLength < 0 )
            {
                ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
                LogError( ( "snprintf returns fail %d", writtenLength ) );
                break;
            }
            else
            {
                outputLength += lineLength + 4;
                pCurOutput += lineLength + 4;
            }

            pCurSdp = pNext + 1;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( pTail > pCurSdp )
        {
            /* Copy the ending string. */
            lineLength = pTail - pCurSdp;
            memcpy( pCurOutput, pCurSdp, lineLength );

            outputLength += lineLength;
            pCurOutput += lineLength;
            pCurSdp += lineLength;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        *pSdpConvertedContentLength = outputLength;
    }

    return ret;
}

SdpControllerResult_t SdpController_SerializeSdpMessage( SdpControllerMessageType_t messageType,
                                                         SdpControllerSdpDescription_t * pSdpDescription,
                                                         char * pSdpMessage,
                                                         size_t * pSdpMessageLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    int written;
    char * pCurrentOutput = pSdpMessage;
    size_t outputBufferWrittenSize = 0U, remainSize;

    if( ( pSdpDescription == NULL ) || ( pSdpMessage == NULL ) || ( pSdpMessageLength == NULL ) )
    {
        ret = SDP_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        remainSize = *pSdpMessageLength - outputBufferWrittenSize;
        written = snprintf( pCurrentOutput, remainSize, SDP_CONTROLLER_MESSAGE_TEMPLATE_HEAD, messageType == SDP_CONTROLLER_MESSAGE_TYPE_OFFER ? "offer" : "answer" );

        if( written < 0 )
        {
            LogError( ( "Unexpected behavior, snprintf returns %d", written ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        }
        else if( written == remainSize )
        {
            LogError( ( "output buffer full" ) );
            ret = SDP_CONTROLLER_RESULT_SDP_CONVERTED_BUFFER_TOO_SMALL;
        }
        else
        {
            pCurrentOutput += written;
            outputBufferWrittenSize += written;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        remainSize = *pSdpMessageLength - outputBufferWrittenSize;
        ret = serializeSdpMessage( pSdpDescription, pCurrentOutput, &remainSize );
        if( ret == SDP_CONTROLLER_RESULT_OK )
        {
            /* remainSize is updated to written length in serializeSdpMessage. */
            pCurrentOutput += remainSize;
            outputBufferWrittenSize += remainSize;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        remainSize = *pSdpMessageLength - outputBufferWrittenSize;
        written = snprintf( pCurrentOutput, remainSize, SDP_CONTROLLER_MESSAGE_TEMPLATE_TAIL );

        if( written < 0 )
        {
            LogError( ( "Unexpected behavior, snprintf returns %d", written ) );
            ret = SDP_CONTROLLER_RESULT_SDP_FAIL_SNPRINTF;
        }
        else if( written == remainSize )
        {
            LogError( ( "output buffer full" ) );
            ret = SDP_CONTROLLER_RESULT_SDP_CONVERTED_BUFFER_TOO_SMALL;
        }
        else
        {
            pCurrentOutput += written;
            outputBufferWrittenSize += written;
        }
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        /* Update written length for user. */
        *pSdpMessageLength = outputBufferWrittenSize;
    }

    return ret;
}

void SdpController_PopulateSessionOrigin( char ** ppBuffer,
                                          size_t * pBufferLength,
                                          SdpControllerOrigin_t * pOrigin )
{
    pOrigin->pUserName = SDP_CONTROLLER_ORIGIN_DEFAULT_USER_NAME;
    pOrigin->userNameLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_USER_NAME );
    pOrigin->sessionId = rand();
    pOrigin->sessionVersion = SDP_CONTROLLER_ORIGIN_DEFAULT_SESSION_VERSION;
    pOrigin->sdpConnectionInformation.pNetworkType = SDP_CONTROLLER_ORIGIN_DEFAULT_NET_TYPE;
    pOrigin->sdpConnectionInformation.networkTypeLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_NET_TYPE );
    pOrigin->sdpConnectionInformation.pAddressType = SDP_CONTROLLER_ORIGIN_IPV4_TYPE;
    pOrigin->sdpConnectionInformation.addressTypeLength = strlen( SDP_CONTROLLER_ORIGIN_IPV4_TYPE );
    pOrigin->sdpConnectionInformation.pConnectionAddress = SDP_CONTROLLER_ORIGIN_DEFAULT_IP_ADDRESS;
    pOrigin->sdpConnectionInformation.connectionAddressLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_IP_ADDRESS );
}

SdpControllerResult_t SdpController_PopulateMediaDescriptions( char ** ppBuffer,
                                                               size_t * pBufferLength,
                                                               SdpControllerSdpDescription_t * pSdpLocalDescription,
                                                               SdpControllerSdpDescription_t * pSdpRemoteDescription,
                                                               PeerConnectionContext_t * pPeerConnectionContext,
                                                               const char * pLocalFingerprint,
                                                               size_t localFingerprintLength )
{
    SdpControllerResult_t ret = SDP_CONTROLLER_RESULT_OK;
    PeerConnectionResult_t peerConnectionResult;
    int i;
    const Transceiver_t * pTransceivers[PEER_CONNECTION_TRANSCEIVER_MAX_COUNT] = {NULL}, * pTransceiver = NULL;
    size_t transceiversCount = PEER_CONNECTION_TRANSCEIVER_MAX_COUNT;
    uint8_t isTransceiverPopulated[ PEER_CONNECTION_TRANSCEIVER_MAX_COUNT ] = {0};
    uint32_t chosenCodec = 0;

    peerConnectionResult = PeerConnection_GetTransceivers( pPeerConnectionContext, pTransceivers, &transceiversCount );
    if( peerConnectionResult != PEER_CONNECTION_RESULT_OK )
    {
        LogError( ( "Fail to get transceivers, return: %d", peerConnectionResult ) );
        ret = SDP_CONTROLLER_RESULT_SDP_FAIL_GET_TRANSCEIVERS;
    }

    if( ret == SDP_CONTROLLER_RESULT_OK )
    {
        if( pSdpRemoteDescription )
        {
            /* Get remote SDP offer, reply with same type oder to match m-lines */
            for( i = 0; i < pSdpRemoteDescription->mediaCount; i++ )
            {
                pTransceiver = OccupyProperTransceiver( &pSdpRemoteDescription->mediaDescriptions[i], pTransceivers, transceiversCount, isTransceiverPopulated, &chosenCodec );

                if( pTransceiver )
                {
                    if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
                    {
                        pSdpLocalDescription->quickAccess.isVideoCodecPayloadSet = 1;
                        pSdpLocalDescription->quickAccess.videoCodecPayload = SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpRemoteDescription->quickAccess.isVideoCodecPayloadSet = 1;
                        pSdpRemoteDescription->quickAccess.videoCodecPayload = SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpLocalDescription->quickAccess.videoCodecRtxPayload = SDP_CONTROLLER_GET_RTX_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpRemoteDescription->quickAccess.videoCodecRtxPayload = SDP_CONTROLLER_GET_RTX_CODEC_FROM_PAYLOAD( chosenCodec );
                    }
                    else if( pTransceiver->trackKind == TRANSCEIVER_TRACK_KIND_AUDIO )
                    {
                        pSdpLocalDescription->quickAccess.isAudioCodecPayloadSet = 1;
                        pSdpLocalDescription->quickAccess.audioCodecPayload = SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpRemoteDescription->quickAccess.isAudioCodecPayloadSet = 1;
                        pSdpRemoteDescription->quickAccess.audioCodecPayload = SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpLocalDescription->quickAccess.audioCodecRtxPayload = SDP_CONTROLLER_GET_RTX_CODEC_FROM_PAYLOAD( chosenCodec );
                        pSdpRemoteDescription->quickAccess.audioCodecRtxPayload = SDP_CONTROLLER_GET_RTX_CODEC_FROM_PAYLOAD( chosenCodec );
                    }
                    else
                    {
                        LogError( ( "Unknown track kind, %d", pTransceiver->trackKind ) );
                        break;
                    }

                    ret = PopulateSingleMedia( ppBuffer, pBufferLength, pSdpLocalDescription, pSdpRemoteDescription, pTransceiver, pPeerConnectionContext, SDP_CONTROLLER_GET_APT_CODEC_FROM_PAYLOAD( chosenCodec ), pLocalFingerprint, localFingerprintLength );
                    if( ret != SDP_CONTROLLER_RESULT_OK )
                    {
                        LogWarn( ( "Fail to pupolate media, ret: %d", ret ) );
                        break;
                    }
                }
                else
                {
                    LogWarn( ( "No tranceiver found for idx: %d", pSdpRemoteDescription->mediaCount ) );
                }
            }
        }
        else
        {
            /* We're generating SDP offer, generate it in our order. */
            for( i = 0; i < transceiversCount; i++ )
            {
                isTransceiverPopulated[ i ] = 1;
                chosenCodec = GetDefaultCodec( pTransceivers[i]->codecBitMap );
                ret = PopulateSingleMedia( ppBuffer, pBufferLength, pSdpLocalDescription, NULL, pTransceivers[i], pPeerConnectionContext, chosenCodec, pLocalFingerprint, localFingerprintLength );
                if( ret != SDP_CONTROLLER_RESULT_OK )
                {
                    LogWarn( ( "Fail to pupolate media, ret: %d", ret ) );
                    break;
                }

                if( pTransceivers[i]->trackKind == TRANSCEIVER_TRACK_KIND_VIDEO )
                {
                    pSdpLocalDescription->quickAccess.isVideoCodecPayloadSet = 1;
                    pSdpLocalDescription->quickAccess.videoCodecPayload = chosenCodec;
                    pSdpRemoteDescription->quickAccess.isVideoCodecPayloadSet = 1;
                    pSdpRemoteDescription->quickAccess.videoCodecPayload = chosenCodec;
                }
                else if( pTransceivers[i]->trackKind == TRANSCEIVER_TRACK_KIND_AUDIO )
                {
                    pSdpLocalDescription->quickAccess.isAudioCodecPayloadSet = 1;
                    pSdpLocalDescription->quickAccess.audioCodecPayload = chosenCodec;
                    pSdpRemoteDescription->quickAccess.isAudioCodecPayloadSet = 1;
                    pSdpRemoteDescription->quickAccess.audioCodecPayload = chosenCodec;
                }
                else
                {
                    LogError( ( "Unknown track kind, %d", pTransceivers[i]->trackKind ) );
                    break;
                }
            }
        }
    }

    return ret;
}
