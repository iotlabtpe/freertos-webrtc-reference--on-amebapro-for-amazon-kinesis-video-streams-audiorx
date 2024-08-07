#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logging.h"
#include "sdp_controller.h"
#include "demo_data_types.h"

const char attributeMidValue0[] = "0";
const char attributeMidValue1[] = "1";

// const char audioAttribute0Name[] = "candidate";
// const char audioAttribute0Value[] = "0 1 udp 2130706431 172.26.66.7 58246 typ host raddr 0.0.0.0 rport 0 generation 0 network-cost 999";
const char audioAttribute1Name[] = "msid";
const char audioAttribute1Value[] = "myKvsVideoStream myAudioTrack";
const char audioAttribute2Name[] = "ssrc";
const char audioAttribute2Value[] = "1427941850 cname:fPXvBF4p7CVUy8HQ";
const char audioAttribute3Name[] = "ssrc";
const char audioAttribute3Value[] = "1427941850 msid:myKvsVideoStream myAudioTrack";
const char audioAttribute4Name[] = "ssrc";
const char audioAttribute4Value[] = "1427941850 mslabel:myKvsVideoStream";
const char audioAttribute5Name[] = "ssrc";
const char audioAttribute5Value[] = "1427941850 label:myAudioTrack";
const char audioAttribute6Name[] = "rtcp";
const char audioAttribute6Value[] = "9 IN IP4 0.0.0.0";
const char audioAttribute7Name[] = "ice-ufrag";
const char audioAttribute7Value[] = "GnjB";
const char audioAttribute8Name[] = "ice-pwd";
const char audioAttribute8Value[] = "eu8hMmfpUkEU3t1DfJb+/J3e";
const char audioAttribute9Name[] = "ice-options";
const char audioAttribute9Value[] = "trickle";
const char audioAttribute10Name[] = "fingerprint";
const char audioAttribute10Value[] = "sha-256 27:22:01:EC:8F:37:2B:9D:1D:6C:77:A7:8F:9B:19:8F:1B:C1:AA:56:33:2F:1A:19:30:85:06:C7:7D:84:FD:2A";
const char audioAttribute11Name[] = "setup";
const char audioAttribute11Value[] = "active";
const char audioAttribute12Name[] = "mid";
const char audioAttribute13Name[] = "sendrecv";
const char audioAttribute14Name[] = "rtcp-mux";
const char audioAttribute15Name[] = "rtpmap";
const char audioAttribute15Value[] = "111 opus/48000/2";
const char audioAttribute16Name[] = "fmtp";
const char audioAttribute16Value[] = "111 minptime=10;useinbandfec=1";
const char audioAttribute17Name[] = "rtcp-fb";
const char audioAttribute17Value[] = "111 goog-remb";
const char audioAttribute18Name[] = "rtcp-fb";
const char audioAttribute18Value[] = "111 transport-cc";
// const char videoAttribute0Name[] = "candidate";
// const char videoAttribute0Value[] = "0 1 udp 2130706431 172.26.66.7 58246 typ host raddr 0.0.0.0 rport 0 generation 0 network-cost 999";
const char videoAttribute1Name[] = "msid";
const char videoAttribute1Value[] = "myKvsVideoStream myVideoTrack";
const char videoAttribute2Name[] = "ssrc";
const char videoAttribute2Value[] = "351461057 cname:fPXvBF4p7CVUy8HQ";
const char videoAttribute3Name[] = "ssrc";
const char videoAttribute3Value[] = "351461057 msid:myKvsVideoStream myVideoTrack";
const char videoAttribute4Name[] = "ssrc";
const char videoAttribute4Value[] = "351461057 mslabel:myKvsVideoStream";
const char videoAttribute5Name[] = "ssrc";
const char videoAttribute5Value[] = "351461057 label:myVideoTrack";
const char videoAttribute6Name[] = "rtcp";
const char videoAttribute6Value[] = "9 IN IP4 0.0.0.0";
const char videoAttribute7Name[] = "ice-ufrag";
const char videoAttribute7Value[] = "GnjB";
const char videoAttribute8Name[] = "ice-pwd";
const char videoAttribute8Value[] = "eu8hMmfpUkEU3t1DfJb+/J3e";
const char videoAttribute9Name[] = "ice-options";
const char videoAttribute9Value[] = "trickle";
const char videoAttribute10Name[] = "fingerprint";
const char videoAttribute10Value[] = "sha-256 27:22:01:EC:8F:37:2B:9D:1D:6C:77:A7:8F:9B:19:8F:1B:C1:AA:56:33:2F:1A:19:30:85:06:C7:7D:84:FD:2A";
const char videoAttribute11Name[] = "setup";
const char videoAttribute11Value[] = "active";
const char videoAttribute12Name[] = "mid";
const char videoAttribute13Name[] = "sendrecv";
const char videoAttribute14Name[] = "rtcp-mux";
const char videoAttribute15Name[] = "rtcp-rsize";
const char videoAttribute16Name[] = "rtpmap";
const char videoAttribute16Value[] = "106 H264/90000";
const char videoAttribute17Name[] = "rtcp-fb";
const char videoAttribute17Value[] = "106 nack pli";
const char videoAttribute18Name[] = "fmtp";
const char videoAttribute18Value[] = "106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";
const char videoAttribute19Name[] = "rtcp-fb";
const char videoAttribute19Value[] = "106 goog-remb";
const char videoAttribute20Name[] = "rtcp-fb";
const char videoAttribute20Value[] = "106 transport-cc";

static SdpControllerAttributes_t *MatchAttributesValuePrefix( SdpControllerAttributes_t *pAttributes, size_t attributeNum, const char *pPattern, size_t patternLength )
{
    SdpControllerAttributes_t *pFound = NULL;
    int i;

    if( pAttributes == NULL || pPattern == NULL )
    {
        LogError( ("Invalid input") );
    }
    else
    {
        for( i=0 ; i<attributeNum ; i++ )
        {
            if( (pAttributes + i)->attributeValueLength >= patternLength &&
                strncmp( (pAttributes + i)->pAttributeValue, pPattern, patternLength ) == 0 )
            {
                pFound = pAttributes + i;
            }
        }
    }

    return pFound;
}

static int AddSessionAttributeGroup( char *pBuffer, size_t remainSize, SdpControllerSdpDescription_t *pLocalSdpDescription, SdpControllerSdpDescription_t *pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char *pCurBuffer = pBuffer;
    int i;
    SdpControllerAttributes_t *pRemoteAttribute = NULL;

    if( pBuffer == NULL ||
        pLocalSdpDescription == NULL )
    {
        totalWritten = -1;
        LogError( ("Invalid input") );
    }

    /* Append attribute name group. */
    if( totalWritten >= 0 )
    {
        written = snprintf( pCurBuffer, remainSize, "group" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for attribute name" ) );
        }
        else
        {
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeName = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeNameLength = strlen( pCurBuffer );

            pCurBuffer += written;
            remainSize -= written;
            totalWritten += written;
        }
    }
    
    /* Append attribute value BUNDLE. */
    if( totalWritten >= 0 )
    {
        /* If we have SDP offer, reuse the BUNDLE string from it. */
        if( pRemoteSdpDescription != NULL )
        {
            pRemoteAttribute = MatchAttributesValuePrefix( pRemoteSdpDescription->attributes, SDP_CONTROLLER_MAX_SDP_ATTRIBUTES_COUNT, "BUNDLE", strlen( "BUNDLE" ) );
        }

        if( pRemoteAttribute )
        {
            written = snprintf( pCurBuffer, remainSize, "%.*s",
                                ( int ) pRemoteAttribute->attributeValueLength,
                                pRemoteAttribute->pAttributeValue );
            if( written < 0 )
            {
                totalWritten = -1;
                LogError( ( "snprintf return unexpected value %d", written ) );
            }
            else if( written == remainSize )
            {
                totalWritten = -2;
                LogError( ( "buffer has no space for attribute value" ) );
            }
            else
            {
                pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeValue = pCurBuffer;
                pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeValueLength = strlen( pCurBuffer );

                totalWritten += written;
            }
        }
    }

    /* Append attribute value BUNDLE if not ready from previous step. */
    if( totalWritten >= 0 && pRemoteAttribute == NULL )
    {
        written = snprintf( pCurBuffer, remainSize, "BUNDLE" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for attribute value" ) );
        }
        else
        {
            char *pAppendNumber = pCurBuffer + written;
            int offset = 0;

            totalWritten += written;

            for( i=0 ; i<pLocalSdpDescription->mediaCount ; i++ )
            {
                written = snprintf( pAppendNumber + offset, remainSize - offset, " %d", i );
                if( written < 0 )
                {
                    totalWritten = -1;
                    LogError( ( "snprintf return unexpected value %d", written ) );
                    break;
                }
                else if( written == remainSize - offset )
                {
                    totalWritten = -2;
                    LogError( ( "buffer has no space for attribute value" ) );
                    break;
                }
                else
                {
                    offset += written;
                }
            }

            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeValue = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeValueLength = strlen( pCurBuffer );
            totalWritten += offset;
        }
    }

    /* Update session attribute count. */
    if( totalWritten >= 0 )
    {
        pLocalSdpDescription->sessionAttributesCount++;
    }

    return totalWritten;
}

static int AddSessionAttributeIceOptions( char *pBuffer, size_t remainSize, SdpControllerSdpDescription_t *pLocalSdpDescription, SdpControllerSdpDescription_t *pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char *pCurBuffer = pBuffer;

    ( void ) pRemoteSdpDescription;

    if( pBuffer == NULL ||
        pLocalSdpDescription == NULL )
    {
        totalWritten = -1;
        LogError( ("Invalid input") );
    }

    if( totalWritten >= 0 )
    {
        written = snprintf( pCurBuffer, remainSize, "ice-options" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for session attributes" ) );
        }
        else
        {
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeName = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeNameLength = strlen( pCurBuffer );

            pCurBuffer += written;
            remainSize -= written;
            totalWritten += written;
        }
    }

    if( totalWritten >= 0 )
    {
        written = snprintf( pCurBuffer, remainSize, "trickle" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for session attributes" ) );
        }
        else
        {
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeValue = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeValueLength = strlen( pCurBuffer );

            totalWritten += written;
            pLocalSdpDescription->sessionAttributesCount++;
        }
    }

    return totalWritten;
}

static int AddSessionAttributeMsidSemantic( char *pBuffer, size_t remainSize, SdpControllerSdpDescription_t *pLocalSdpDescription, SdpControllerSdpDescription_t *pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char *pCurBuffer = pBuffer;

    ( void ) pRemoteSdpDescription;

    if( pBuffer == NULL ||
        pLocalSdpDescription == NULL )
    {
        totalWritten = -1;
        LogError( ("Invalid input") );
    }

    if( totalWritten >= 0 )
    {
        written = snprintf( pCurBuffer, remainSize, "msid-semantic" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for session attributes" ) );
        }
        else
        {
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeName = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeNameLength = strlen( pCurBuffer );

            pCurBuffer += written;
            remainSize -= written;
            totalWritten += written;
        }
    }

    if( totalWritten >= 0 )
    {
        written = snprintf( pCurBuffer, remainSize, " WMS myKvsVideoStream" );
        if( written < 0 )
        {
            totalWritten = -1;
            LogError( ( "snprintf return unexpected value %d", written ) );
        }
        else if( written == remainSize )
        {
            totalWritten = -2;
            LogError( ( "buffer has no space for session attributes" ) );
        }
        else
        {
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].pAttributeValue = pCurBuffer;
            pLocalSdpDescription->attributes[ pLocalSdpDescription->sessionAttributesCount ].attributeValueLength = strlen( pCurBuffer );

            totalWritten += written;
            pLocalSdpDescription->sessionAttributesCount++;
        }
    }

    return totalWritten;
}

static uint8_t storeAndParseSdpOffer( const char *pEventSdpOffer, size_t eventSdpOfferlength, DemoSessionInformation_t *pSessionInDescriptionOffer )
{
    uint8_t skipProcess = 0;
    SdpControllerResult_t retSdpController;
    const char *pSdpContent;
    size_t sdpContentLength;
    char *pSdpBuffer = pSessionInDescriptionOffer->sdpBuffer;
    size_t *pSdpBufferLength = &pSessionInDescriptionOffer->sdpBufferLength;

    /* Store the SDP offer then parse it in poiters structure. */
    retSdpController = SdpController_GetSdpOfferContent( pEventSdpOffer, eventSdpOfferlength, &pSdpContent, &sdpContentLength );
    if( retSdpController != SDP_CONTROLLER_RESULT_OK )
    {
        LogError( ( "Unable to find SDP offer content, result: %d", retSdpController ) );
        skipProcess = 1;
    }

    if( !skipProcess )
    {
        if( sdpContentLength > DEMO_SDP_BUFFER_MAX_LENGTH )
        {
            LogError( ( "No enough memory to store SDP offer" ) );
            skipProcess = 1;
        }
        else
        {
            /* Keep SDP concent in global buffer after replacing newline, then we can keep accessing the parsed result in pointers structure. */
            pSessionInDescriptionOffer->sdpBufferLength = DEMO_SDP_BUFFER_MAX_LENGTH;
            retSdpController = SdpController_DeserializeSdpContentNewline( pSdpContent, sdpContentLength,
                                                                           &pSdpBuffer, pSdpBufferLength );
            if( retSdpController != SDP_CONTROLLER_RESULT_OK )
            {
                skipProcess = 1;
                LogError( ( "Unable to convert SDP offer, result: %d", retSdpController ) );
            }
        }
    }

    if( !skipProcess )
    {
        retSdpController = SdpController_DeserializeSdpOffer( pSessionInDescriptionOffer->sdpBuffer,
                                                              pSessionInDescriptionOffer->sdpBufferLength,
                                                              &pSessionInDescriptionOffer->sdpDescription );
        if( retSdpController != SDP_CONTROLLER_RESULT_OK )
        {
            skipProcess = 1;
            LogError( ( "Unable to deserialize SDP offer, result: %d", retSdpController ) );
        }
    }

    return skipProcess;
}

static uint8_t populateSessionAttributes( char **ppBuffer, size_t *pBufferLength, SdpControllerSdpDescription_t *pRemoteSdpDescription, SdpControllerSdpDescription_t *pLocalSdpDescription )
{
    uint8_t skipProcess = 0;
    int written;
    size_t remainSize = *pBufferLength;
    char *pCurBuffer = *ppBuffer;

    if( ppBuffer == NULL ||
        *ppBuffer == NULL ||
        pBufferLength == NULL ||
        pRemoteSdpDescription == NULL ||
        pLocalSdpDescription == NULL )
    {
        LogError( ("Invalid input.") );
        skipProcess = 1;
    }

    if( skipProcess == 0 )
    {
        /* a=group:BINDLE 0 1 ...
         * Note that we need to session media count to populate this value. */
        written = AddSessionAttributeGroup( pCurBuffer, remainSize, pLocalSdpDescription, pRemoteSdpDescription );
        if( written < 0 )
        {
            skipProcess = 1;
            LogError( ( "Fail to add group to session attribute with return %d", written ) );
        }
        else
        {
            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* ice-options. */
    if( !skipProcess )
    {
        /* a=ice-options:trickle */
        written = AddSessionAttributeIceOptions( pCurBuffer, remainSize, pLocalSdpDescription, pRemoteSdpDescription );
        if( written < 0 )
        {
            skipProcess = 1;
            LogError( ( "Fail to add ice-options to session attribute with return %d", written ) );
        }
        else
        {
            pCurBuffer += written;
            remainSize -= written;
        }
    }

    /* msid-semantic */
    if( !skipProcess )
    {
        /* a=msid-semantic: WMS myKvsVideoStream */
        written = AddSessionAttributeMsidSemantic( pCurBuffer, remainSize, pLocalSdpDescription, pRemoteSdpDescription );
        if( written < 0 )
        {
            skipProcess = 1;
            LogError( ( "Fail to add ice-options to session attribute with return %d", written ) );
        }
        else
        {
            pCurBuffer += written;
            remainSize -= written;
        }
    }

    if( !skipProcess )
    {
        *ppBuffer = pCurBuffer;
        *pBufferLength = remainSize;
    }

    return skipProcess;
}

// static void PrintPopulatedSessionDesceiption( DemoSessionInformation_t *pSessionDescription )
// {
//     int i, j;

//     if( pSessionDescription )
//     {
//         LogDebug( ("Version: %lu", pSessionDescription->sdpDescription.version) );

//         LogDebug( ("Origin - user name(%u): %.*s", pSessionDescription->sdpDescription.origin.userNameLength,
//                                             ( int ) pSessionDescription->sdpDescription.origin.userNameLength,
//                                             pSessionDescription->sdpDescription.origin.pUserName) );
//         LogDebug( ("Origin - session ID: %lu", pSessionDescription->sdpDescription.origin.sessionId) );
//         LogDebug( ("Origin - session version: %lu", pSessionDescription->sdpDescription.origin.sessionVersion) );

//         LogDebug( ("Origin - connection info - network type(%u): %.*s", pSessionDescription->sdpDescription.origin.sdpConnectionInformation.networkTypeLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.origin.sdpConnectionInformation.networkTypeLength,
//                                                                       pSessionDescription->sdpDescription.origin.sdpConnectionInformation.pNetworkType) );
//         LogDebug( ("Origin - connection info - address type(%u): %.*s", pSessionDescription->sdpDescription.origin.sdpConnectionInformation.addressTypeLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.origin.sdpConnectionInformation.addressTypeLength,
//                                                                       pSessionDescription->sdpDescription.origin.sdpConnectionInformation.pAddressType) );
//         LogDebug( ("Origin - connection info - address(%u): %.*s", pSessionDescription->sdpDescription.origin.sdpConnectionInformation.connectionAddressLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.origin.sdpConnectionInformation.connectionAddressLength,
//                                                                       pSessionDescription->sdpDescription.origin.sdpConnectionInformation.pConnectionAddress) );

//         LogDebug( ("Session name(%u): %.*s", pSessionDescription->sdpDescription.sessionNameLength,
//                                              ( int ) pSessionDescription->sdpDescription.sessionNameLength,
//                                              pSessionDescription->sdpDescription.pSessionName) );
//         LogDebug( ("Session description(%u): %.*s", pSessionDescription->sdpDescription.sessionInformationLength,
//                                              ( int ) pSessionDescription->sdpDescription.sessionInformationLength,
//                                              pSessionDescription->sdpDescription.pSessionInformation) );
//         LogDebug( ("URI(%u): %.*s", pSessionDescription->sdpDescription.uriLength,
//                                              ( int ) pSessionDescription->sdpDescription.uriLength,
//                                              pSessionDescription->sdpDescription.pUri) );
//         LogDebug( ("Email address(%u): %.*s", pSessionDescription->sdpDescription.emailAddressLength,
//                                              ( int ) pSessionDescription->sdpDescription.emailAddressLength,
//                                              pSessionDescription->sdpDescription.pEmailAddress) );
//         LogDebug( ("Phone number(%u): %.*s", pSessionDescription->sdpDescription.phoneNumberLength,
//                                              ( int ) pSessionDescription->sdpDescription.phoneNumberLength,
//                                              pSessionDescription->sdpDescription.pPhoneNumber) );

//         LogDebug( ("Session - connection info - network type(%u): %.*s", pSessionDescription->sdpDescription.connectionInformation.networkTypeLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.connectionInformation.networkTypeLength,
//                                                                       pSessionDescription->sdpDescription.connectionInformation.pNetworkType) );
//         LogDebug( ("Session - connection info - address type(%u): %.*s", pSessionDescription->sdpDescription.connectionInformation.addressTypeLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.connectionInformation.addressTypeLength,
//                                                                       pSessionDescription->sdpDescription.connectionInformation.pAddressType) );
//         LogDebug( ("Session - connection info - address(%u): %.*s", pSessionDescription->sdpDescription.connectionInformation.connectionAddressLength,
//                                                                       ( int ) pSessionDescription->sdpDescription.connectionInformation.connectionAddressLength,
//                                                                       pSessionDescription->sdpDescription.connectionInformation.pConnectionAddress) );

//         LogDebug( ("Time description, start time: %lu, stop time: %lu", pSessionDescription->sdpDescription.timingDescription.startTime,
//                                                                         pSessionDescription->sdpDescription.timingDescription.stopTime) );

//         LogDebug( ("Session attributes number: %u", pSessionDescription->sdpDescription.sessionAttributesCount) );
//         for( i=0; i<pSessionDescription->sdpDescription.sessionAttributesCount; i++ )
//         {
//             LogDebug( ("Session attribute idx(%d), name(%d): %.*s, value(%d): %.*s", i,
//                         pSessionDescription->sdpDescription.attributes[i].attributeNameLength, ( int ) pSessionDescription->sdpDescription.attributes[i].attributeNameLength, pSessionDescription->sdpDescription.attributes[i].pAttributeName,
//                         pSessionDescription->sdpDescription.attributes[i].attributeValueLength, ( int ) pSessionDescription->sdpDescription.attributes[i].attributeValueLength, pSessionDescription->sdpDescription.attributes[i].pAttributeValue) );
//         }
        
//         LogDebug( ("Session media number: %u", pSessionDescription->sdpDescription.mediaCount) );
//         for( i=0; i<pSessionDescription->sdpDescription.mediaCount; i++ )
//         {
//             // SdpControllerAttributes_t attributes[ SDP_CONTROLLER_MAX_SDP_ATTRIBUTES_COUNT ];

//             // uint8_t mediaAttributesCount;
//             LogDebug( ("Media name(%d): %.*s", pSessionDescription->sdpDescription.mediaDescriptions[i].mediaNameLength,
//                                                ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].mediaNameLength,
//                                                pSessionDescription->sdpDescription.mediaDescriptions[i].pMediaName) );
//             LogDebug( ("Media title(%d): %.*s", pSessionDescription->sdpDescription.mediaDescriptions[i].mediaTitleLength,
//                                                ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].mediaTitleLength,
//                                                pSessionDescription->sdpDescription.mediaDescriptions[i].pMediaTitle) );

//             LogDebug( ("Media - connection info - network type(%u): %.*s", pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.networkTypeLength,
//                                                                         ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.networkTypeLength,
//                                                                         pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.pNetworkType) );
//             LogDebug( ("Media - connection info - address type(%u): %.*s", pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.addressTypeLength,
//                                                                         ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.addressTypeLength,
//                                                                         pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.pAddressType) );
//             LogDebug( ("Media - connection info - address(%u): %.*s", pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.connectionAddressLength,
//                                                                         ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.connectionAddressLength,
//                                                                         pSessionDescription->sdpDescription.mediaDescriptions[i].connectionInformation.pConnectionAddress) );

//             LogDebug( ("Media attributes number: %u", pSessionDescription->sdpDescription.mediaDescriptions[i].mediaAttributesCount) );
//             for( j=0; j<pSessionDescription->sdpDescription.mediaDescriptions[i].mediaAttributesCount; j++ )
//             {
//                 LogDebug( ("Media attribute idx(%d), name(%d): %.*s, value(%d): %.*s", i,
//                             pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].attributeNameLength, ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].attributeNameLength, pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].pAttributeName,
//                             pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].attributeValueLength, ( int ) pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].attributeValueLength, pSessionDescription->sdpDescription.mediaDescriptions[i].attributes[j].pAttributeValue) );
//             }
//         }
//     }
// }

uint8_t populateSdpContent( DemoSessionInformation_t *pRemoteSessionDescription, DemoSessionInformation_t *pLocalSessionDescription, PeerConnectionContext_t *pPeerConnectionContext )
{
    uint8_t skipProcess = 0;
    size_t remainLength = DEMO_SDP_BUFFER_MAX_LENGTH;
    char *pSdpBuffer = NULL;
    SdpControllerResult_t retSdpController;
    
    if( pRemoteSessionDescription == NULL || pLocalSessionDescription == NULL || pPeerConnectionContext == NULL )
    {
        LogError( ("Invalid input, pRemoteSessionDescription: %p, pLocalSessionDescription: %p, pPeerConnectionContext: %p",
                    pRemoteSessionDescription, pLocalSessionDescription, pPeerConnectionContext) );
        skipProcess = 1;
    }

    if( !skipProcess )
    {
        pSdpBuffer = &pLocalSessionDescription->sdpBuffer[0];
        memset( pLocalSessionDescription, 0, sizeof( DemoSessionInformation_t ) );

        /* Add media descriptions. */
        retSdpController = SdpController_PopulateMediaDescriptions( &pSdpBuffer, &remainLength, &pLocalSessionDescription->sdpDescription, &pRemoteSessionDescription->sdpDescription, pPeerConnectionContext );
        if( retSdpController != SDP_CONTROLLER_RESULT_OK )
        {
            LogError( ("Fail to populate media descriptions, return: %d", retSdpController) );
            skipProcess = 1;
        }
    }

    if( !skipProcess )
    {
        /* Add session descriptions.
         * Note that we need to session media count to populate session group attribute,
         * so this have to do after populate media sessions. */
        /* Session version. */
        pLocalSessionDescription->sdpDescription.version = 0U;

        /* Session origin. */
        SdpController_PopulateSessionOrigin( &pSdpBuffer, &remainLength, &pLocalSessionDescription->sdpDescription.origin );

        /* Session name. */
        pLocalSessionDescription->sdpDescription.pSessionName = SDP_CONTROLLER_ORIGIN_DEFAULT_SESSION_NAME;
        pLocalSessionDescription->sdpDescription.sessionNameLength = strlen( SDP_CONTROLLER_ORIGIN_DEFAULT_SESSION_NAME );

        /* Session timing description. */
        pLocalSessionDescription->sdpDescription.timingDescription.startTime = 0U;
        pLocalSessionDescription->sdpDescription.timingDescription.stopTime = 0U;

        skipProcess = populateSessionAttributes( &pSdpBuffer, &remainLength, &pRemoteSessionDescription->sdpDescription, &pLocalSessionDescription->sdpDescription );
        LogDebug( ("After populateSessionAttributes, skipProcess: %u", skipProcess) );
    }

    return skipProcess;
}

uint8_t serializeSdpMessage( DemoSessionInformation_t *pSessionInDescriptionAnswer, DemoContext_t *pDemoContext )
{
    uint8_t skipProcess = 0;
    SdpControllerResult_t retSdpController;

    pDemoContext->sdpConstructedBufferLength = DEMO_SDP_BUFFER_MAX_LENGTH;
    retSdpController = SdpController_SerializeSdpMessage( SDP_CONTROLLER_MESSAGE_TYPE_ANSWER, &pSessionInDescriptionAnswer->sdpDescription, pDemoContext->sdpConstructedBuffer, &pDemoContext->sdpConstructedBufferLength );
    if( retSdpController != SDP_CONTROLLER_RESULT_OK )
    {
        LogError( ( "SdpController_SerializeSdpMessage fail, returns %d", retSdpController ) );
        skipProcess = 1;
    }

    if( !skipProcess )
    {
        pSessionInDescriptionAnswer->sdpBufferLength = DEMO_SDP_BUFFER_MAX_LENGTH;
        retSdpController = SdpController_SerializeSdpNewline( pDemoContext->sdpConstructedBuffer, pDemoContext->sdpConstructedBufferLength, pSessionInDescriptionAnswer->sdpBuffer, &pSessionInDescriptionAnswer->sdpBufferLength );
        if( retSdpController != SDP_CONTROLLER_RESULT_OK )
        {
            LogError( ( "SdpController_SerializeSdpNewline fail, returns %d", retSdpController ) );
            skipProcess = 1;
        }
        else
        {
            LogDebug( ( "Serialized SDP answer (%u):\n%.*s", pSessionInDescriptionAnswer->sdpBufferLength,
                                                             ( int ) pSessionInDescriptionAnswer->sdpBufferLength,
                                                             pSessionInDescriptionAnswer->sdpBuffer ) );
        }
    }

    return skipProcess;
}

uint8_t addressSdpOffer( const char *pEventSdpOffer, size_t eventSdpOfferlength, DemoContext_t *pDemoContext )
{
    uint8_t skipProcess = 0;

    skipProcess = storeAndParseSdpOffer( pEventSdpOffer, eventSdpOfferlength, &pDemoContext->sessionInformationSdpOffer );

    return skipProcess;
}
