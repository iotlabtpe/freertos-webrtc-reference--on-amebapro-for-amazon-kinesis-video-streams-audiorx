#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logging.h"
#include "sdp_controller.h"
#include "demo_data_types.h"

static SdpControllerAttributes_t * MatchAttributesValuePrefix( SdpControllerAttributes_t * pAttributes,
                                                               size_t attributeNum,
                                                               const char * pPattern,
                                                               size_t patternLength )
{
    SdpControllerAttributes_t * pFound = NULL;
    int i;

    if( ( pAttributes == NULL ) || ( pPattern == NULL ) )
    {
        LogError( ( "Invalid input" ) );
    }
    else
    {
        for( i = 0; i < attributeNum; i++ )
        {
            if( ( ( pAttributes + i )->attributeValueLength >= patternLength ) &&
                ( strncmp( ( pAttributes + i )->pAttributeValue, pPattern, patternLength ) == 0 ) )
            {
                pFound = pAttributes + i;
            }
        }
    }

    return pFound;
}

static int AddSessionAttributeGroup( char * pBuffer,
                                     size_t remainSize,
                                     SdpControllerSdpDescription_t * pLocalSdpDescription,
                                     SdpControllerSdpDescription_t * pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char * pCurBuffer = pBuffer;
    int i;
    SdpControllerAttributes_t * pRemoteAttribute = NULL;

    if( ( pBuffer == NULL ) ||
        ( pLocalSdpDescription == NULL ) )
    {
        totalWritten = -1;
        LogError( ( "Invalid input" ) );
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
    if( ( totalWritten >= 0 ) && ( pRemoteAttribute == NULL ) )
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
            char * pAppendNumber = pCurBuffer + written;
            int offset = 0;

            totalWritten += written;

            for( i = 0; i < pLocalSdpDescription->mediaCount; i++ )
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

static int AddSessionAttributeIceOptions( char * pBuffer,
                                          size_t remainSize,
                                          SdpControllerSdpDescription_t * pLocalSdpDescription,
                                          SdpControllerSdpDescription_t * pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char * pCurBuffer = pBuffer;

    ( void ) pRemoteSdpDescription;

    if( ( pBuffer == NULL ) ||
        ( pLocalSdpDescription == NULL ) )
    {
        totalWritten = -1;
        LogError( ( "Invalid input" ) );
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

static int AddSessionAttributeMsidSemantic( char * pBuffer,
                                            size_t remainSize,
                                            SdpControllerSdpDescription_t * pLocalSdpDescription,
                                            SdpControllerSdpDescription_t * pRemoteSdpDescription )
{
    int totalWritten = 0;
    int written = 0;
    char * pCurBuffer = pBuffer;

    ( void ) pRemoteSdpDescription;

    if( ( pBuffer == NULL ) ||
        ( pLocalSdpDescription == NULL ) )
    {
        totalWritten = -1;
        LogError( ( "Invalid input" ) );
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

static uint8_t storeAndParseSdpOffer( const char * pEventSdpOffer,
                                      size_t eventSdpOfferlength,
                                      DemoSessionInformation_t * pSessionInDescriptionOffer )
{
    uint8_t skipProcess = 0;
    SdpControllerResult_t retSdpController;
    const char * pSdpContent;
    size_t sdpContentLength;
    char * pSdpBuffer = pSessionInDescriptionOffer->sdpBuffer;
    size_t * pSdpBufferLength = &pSessionInDescriptionOffer->sdpBufferLength;

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

static uint8_t populateSessionAttributes( char ** ppBuffer,
                                          size_t * pBufferLength,
                                          SdpControllerSdpDescription_t * pRemoteSdpDescription,
                                          SdpControllerSdpDescription_t * pLocalSdpDescription )
{
    uint8_t skipProcess = 0;
    int written;
    size_t remainSize = *pBufferLength;
    char * pCurBuffer = *ppBuffer;

    if( ( ppBuffer == NULL ) ||
        ( *ppBuffer == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pRemoteSdpDescription == NULL ) ||
        ( pLocalSdpDescription == NULL ) )
    {
        LogError( ( "Invalid input." ) );
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

uint8_t populateSdpContent( DemoSessionInformation_t * pRemoteSessionDescription,
                            DemoSessionInformation_t * pLocalSessionDescription,
                            PeerConnectionContext_t * pPeerConnectionContext,
                            const char * pLocalFingerprint,
                            size_t localFingerprintLength )
{
    uint8_t skipProcess = 0;
    size_t remainLength = DEMO_SDP_BUFFER_MAX_LENGTH;
    char * pSdpBuffer = NULL;
    SdpControllerResult_t retSdpController;

    if( ( pRemoteSessionDescription == NULL ) || ( pLocalSessionDescription == NULL ) || ( pPeerConnectionContext == NULL ) )
    {
        LogError( ( "Invalid input, pRemoteSessionDescription: %p, pLocalSessionDescription: %p, pPeerConnectionContext: %p",
                    pRemoteSessionDescription, pLocalSessionDescription, pPeerConnectionContext ) );
        skipProcess = 1;
    }

    if( !skipProcess )
    {
        pSdpBuffer = &pLocalSessionDescription->sdpBuffer[0];
        memset( pLocalSessionDescription, 0, sizeof( DemoSessionInformation_t ) );

        /* Add media descriptions. */
        retSdpController = SdpController_PopulateMediaDescriptions( &pSdpBuffer, &remainLength, &pLocalSessionDescription->sdpDescription, &pRemoteSessionDescription->sdpDescription, pPeerConnectionContext, pLocalFingerprint, localFingerprintLength );
        if( retSdpController != SDP_CONTROLLER_RESULT_OK )
        {
            LogError( ( "Fail to populate media descriptions, return: %d", retSdpController ) );
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
        LogDebug( ( "After populateSessionAttributes, skipProcess: %u", skipProcess ) );
    }

    return skipProcess;
}

uint8_t serializeSdpMessage( DemoSessionInformation_t * pSessionInDescriptionAnswer,
                             DemoContext_t * pDemoContext )
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

uint8_t addressSdpOffer( const char * pEventSdpOffer,
                         size_t eventSdpOfferlength,
                         DemoContext_t * pDemoContext )
{
    uint8_t skipProcess = 0;

    skipProcess = storeAndParseSdpOffer( pEventSdpOffer, eventSdpOfferlength, &pDemoContext->sessionInformationSdpOffer );

    return skipProcess;
}
