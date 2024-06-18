#include "logging.h"
#include "wslay_helper.h"
#include "core_http_client.h"

/* Inlucde mbedtls for random/base64 */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

NetworkingWslayContext_t networkingWslayContext;

#define NETWORKING_WSLAY_SEND_TIMEOUT_MS ( 1000 )
#define NETWORKING_WSLAY_RECV_TIMEOUT_MS ( 1000 )
#define NETWORKING_WSLAY_USER_AGENT_NAME_MAX_LENGTH ( 128 )
#define NETWORKING_WSLAY_HOST_NAME_MAX_LENGTH ( 256 )
#define NETWORKING_WSLAY_CLIENT_KEY_RANDOM_LENGTH ( 16 )
#define NETWORKING_WSLAY_CLIENT_KEY_LENGTH ( 24 )
#define NETWORKING_WSLAY_ACCEPT_KEY_LENGTH ( 28 )
#define NETWORKING_WSLAY_STRING_CHANNEL_ARN_PARAM_NAME "X-Amz-ChannelARN"
#define NETWORKING_WSLAY_STRING_CREDENTIAL_PARAM_NAME "X-Amz-Credential"
#define NETWORKING_WSLAY_STRING_DATE_PARAM_NAME "X-Amz-Date"
#define NETWORKING_WSLAY_STRING_EXPIRES_PARAM_NAME "X-Amz-Expires"
#define NETWORKING_WSLAY_STRING_SIGNED_HEADERS_PARAM_NAME "X-Amz-SignedHeaders"
#define NETWORKING_WSLAY_STRING_SIGNATURE_PARAM_NAME "X-Amz-Signature"
#define NETWORKING_WSLAY_STRING_SIGNED_HEADERS_VALUE "host"
#define NETWORKING_WSLAY_STRING_RFC6455_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define NETWORKING_WSLAY_RFC6455_UUID_LENGTH ( 36 )
#define NETWORKING_WSLAY_SHA1_LENGTH ( 20 )
#define NETWORKING_WSLAY_PING_PONG_INTERVAL_SEC ( 10 )
#define NETWORKING_WSLAY_PING_PONG_INTERVAL_TICKS ( pdMS_TO_TICKS( NETWORKING_WSLAY_PING_PONG_INTERVAL_SEC * 1000 ) ) /* 10s to ticks */

#define NETWORKING_WSLAY_STRING_CREDENTIAL_VALUE_TEMPLATE "%.*s/%.*s/%.*s/" NETWORKING_UTILS_KVS_SERVICE_NAME "/aws4_request"

#define NETWORKING_WSLAY_CREDENTIAL_PARAM_DATE_LENGTH ( 8 )
#define NETWORKING_WSLAY_STATIC_CRED_EXPIRES_SECONDS ( 604800 )

#define NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE ( 3 ) // We need 3 char spaces to translate symbols, such as from '/' to "%2F".
#define NETWORKING_WSLAY_URI_ENCODED_FORWARD_SLASH "%2F"

static void GenerateRandomBytes( uint8_t *pBuffer, size_t bufferLength );
static void handleWslayControlMessage( void *pUserData, uint8_t opcode, const uint8_t *pData, size_t dataLength );
static void handleWslayDataMessage( void *pUserData, const uint8_t *pData, size_t dataLength );

static ssize_t wslay_send_callback( wslay_event_context_ptr pCtx, const uint8_t *pData, size_t dataLength, int flags, void *pUserData )
{
    NetworkingWslayContext_t *pContext = ( NetworkingWslayContext_t* ) pUserData;
    TransportSend_t sendFunction = pContext->xTransportInterface.send;
    ssize_t r = (ssize_t)sendFunction( &networkingWslayContext.xNetworkContext, pData, dataLength );

    if( r < 0 )
    {
        wslay_event_set_error( pCtx, WSLAY_ERR_CALLBACK_FAILURE );
        LogError( ("wslay_send_callback failed with return %d", r) );
    }
    else if( r == 0 )
    {
        wslay_event_set_error( pCtx, WSLAY_ERR_WOULDBLOCK );
        LogDebug( ("wslay_send_callback returns 0") );
    }
    else
    {
        /* Sent successfully. */
    }

    return r;
}

static ssize_t wslay_recv_callback( wslay_event_context_ptr pCtx, uint8_t *pData, size_t dataLength, int flags, void *pUserData )
{
    NetworkingWslayContext_t *pContext = ( NetworkingWslayContext_t* ) pUserData;
    TransportRecv_t recvFunction = pContext->xTransportInterface.recv;
    ssize_t r = (ssize_t) recvFunction( &networkingWslayContext.xNetworkContext, pData, dataLength );

    if( r < 0 )
    {
        wslay_event_set_error( pCtx, WSLAY_ERR_CALLBACK_FAILURE );
    }
    else if( r == 0 )
    {
        wslay_event_set_error( pCtx, WSLAY_ERR_WOULDBLOCK );
    }
    else
    {
        /* Recv successfully. */
    }

    return r;
}

static int wslay_genmask_callback( wslay_event_context_ptr pCtx, uint8_t *pBuf, size_t bufLength, void *pUserData )
{
    ( void ) pCtx;
    ( void ) pUserData;

    GenerateRandomBytes( pBuf, bufLength );
    return 0;
}

static void wslay_msg_recv_callback( wslay_event_context_ptr pCtx, const struct wslay_event_on_msg_recv_arg* pArg, void *pUserData )
{
    if( !wslay_is_ctrl_frame(pArg->opcode) )
    {
        handleWslayDataMessage( pUserData, pArg->msg, pArg->msg_length );
    }
    else
    {
        handleWslayControlMessage( pUserData, pArg->opcode, pArg->msg, pArg->msg_length );
    }
}

static void handleWslayControlMessage( void *pUserData, uint8_t opcode, const uint8_t *pData, size_t dataLength )
{
    NetworkingWslayContext_t *pContext = ( NetworkingWslayContext_t* ) pUserData;

    if( opcode == WSLAY_PONG )
    {
        LogInfo( ("<== wss pong") );
    }
    else if( opcode == WSLAY_PING )
    {
        LogInfo( ("<== wss ping, len: %u", dataLength) );
    }
    else if( opcode == WSLAY_CONNECTION_CLOSE )
    {
        LogInfo( ("<== connection close, msg len: %u", dataLength) );
        NetworkingUtils_CloseConnection( &pContext->xNetworkContext );
    }
    else
    {
        LogInfo( ("<== ctrl msg(%u), len: %u", opcode, dataLength) );
    }
}

static void handleWslayDataMessage( void *pUserData, const uint8_t *pData, size_t dataLength )
{
    NetworkingWslayContext_t *pContext = ( NetworkingWslayContext_t* ) pUserData;

    (void) pContext->websocketRxCallback( (char*) pData, dataLength, pContext->pWebsocketRxCallbackContext );
}

static NetworkingWslayResult_t uriEncodedString( char *pSrc, size_t srcLength, char *pDst, size_t *pDstLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    size_t encodedLength = 0, remainLength;
    char *pCurPtr = pSrc, *pEnc = pDst;
    char ch;
    const char alpha[17] = "0123456789ABCDEF";

    if( pSrc == NULL || pDst == NULL || pDstLength == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        // Set the remainLength length
        remainLength = *pDstLength;

        while( ( ( size_t ) ( pCurPtr - pSrc ) < srcLength ) && ( ( ch = *pCurPtr++ ) != '\0') )
        {
            if( ( ch >= 'A' && ch <= 'Z' ) || ( ch >= 'a' && ch <= 'z' ) || ( ch >= '0' && ch <= '9' ) || ch == '_' || ch == '-' || ch == '~' || ch == '.')
            {
                if( remainLength < 1U )
                {
                    ret = NETWORKING_WSLAY_RESULT_URI_ENCODED_BUFFER_TOO_SMALL;
                    break;
                }
                
                encodedLength++;
                *pEnc++ = ch;
                remainLength--;
            }
            else if( ch == '/' )
            {
                if( remainLength < NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE )
                {
                    ret = NETWORKING_WSLAY_RESULT_URI_ENCODED_BUFFER_TOO_SMALL;
                    break;
                }
                
                encodedLength += NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE;
                strncpy( pEnc, NETWORKING_WSLAY_URI_ENCODED_FORWARD_SLASH, remainLength );
                pEnc += NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE;
                remainLength -= NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE;
            }
            else
            {
                if( remainLength < NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE )
                {
                    ret = NETWORKING_WSLAY_RESULT_URI_ENCODED_BUFFER_TOO_SMALL;
                    break;
                }
                
                encodedLength += NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE;
                *pEnc++ = '%';
                *pEnc++ = alpha[ch >> 4];
                *pEnc++ = alpha[ch & 0x0f];
                remainLength -= NETWORKING_WSLAY_URI_ENCODED_CHAR_SIZE;
            }
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        *pDstLength -= remainLength;
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedAlgorithm( char **ppBuffer, size_t *pBufferLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;

    writtenLength = snprintf( *ppBuffer, *pBufferLength, "X-Amz-Algorithm=AWS4-HMAC-SHA256" );

    if( writtenLength < 0 )
    {
        ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
    }
    else if( writtenLength == *pBufferLength )
    {
        ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
    }
    else
    {
        *ppBuffer += writtenLength;
        *pBufferLength -= writtenLength;
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedChannelArn( char **ppBuffer, size_t *pBufferLength, char *pChannelArn, size_t channelArnLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;
    size_t encodedLength;

    /* X-Amz-ChannelARN query parameter. */
    writtenLength = snprintf( *ppBuffer, *pBufferLength, "&X-Amz-ChannelARN=" );

    if( writtenLength < 0 )
    {
        ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
    }
    else if( writtenLength == *pBufferLength )
    {
        ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
    }
    else
    {
        *ppBuffer += writtenLength;
        *pBufferLength -= writtenLength;
    }

    /* X-Amz-ChannelARN value (plaintext). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( *ppBuffer, *pBufferLength, "%.*s",
                                  ( int ) channelArnLength, pChannelArn );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == *pBufferLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            /* Keep the pointer and *pBufferLength for URI encoded. */
        }
    }

    /* X-Amz-ChannelARN value (URI encoded). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        encodedLength = *pBufferLength - writtenLength;
        ret = uriEncodedString( *ppBuffer, writtenLength, (*ppBuffer) + writtenLength, &encodedLength );

        /* Move and update pointer/remain length. */
        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            memmove( *ppBuffer, *ppBuffer + writtenLength, encodedLength );
            *ppBuffer += encodedLength;
            *pBufferLength -= encodedLength;
        }
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedCredential( char **ppBuffer, size_t *pBufferLength, const char *pDate )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;
    size_t encodedLength;

    /* X-Amz-Credential query parameter. */
    writtenLength = snprintf( *ppBuffer, *pBufferLength, "&" NETWORKING_WSLAY_STRING_CREDENTIAL_PARAM_NAME "=" );

    if( writtenLength < 0 )
    {
        ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
    }
    else if( writtenLength == *pBufferLength )
    {
        ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
    }
    else
    {
        *ppBuffer += writtenLength;
        *pBufferLength -= writtenLength;
    }

    /* X-Amz-Credential value (plaintext). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( *ppBuffer, *pBufferLength, NETWORKING_WSLAY_STRING_CREDENTIAL_VALUE_TEMPLATE,
                                  ( int ) networkingWslayContext.credentials.accessKeyIdLength, networkingWslayContext.credentials.pAccessKeyId,
                                  NETWORKING_WSLAY_CREDENTIAL_PARAM_DATE_LENGTH, pDate,
                                  ( int ) networkingWslayContext.credentials.regionLength, networkingWslayContext.credentials.pRegion );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == *pBufferLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            /* Keep the pointer and pBufferLength for URI encoded. */
        }
    }

    /* X-Amz-Credential value (URI encoded) */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        encodedLength = *pBufferLength - writtenLength;
        ret = uriEncodedString( *ppBuffer, writtenLength, *ppBuffer + writtenLength, &encodedLength );

        /* Move and update pointer/remain length. */
        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            memmove( *ppBuffer, *ppBuffer + writtenLength, encodedLength );
            *ppBuffer += encodedLength;
            *pBufferLength -= encodedLength;
        }
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedDate( char **ppBuffer, size_t *pBufferLength, const char *pDate, size_t dateLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;
    size_t encodedLength;

    /* X-Amz-Date query parameter. */
    writtenLength = snprintf( *ppBuffer, *pBufferLength, "&" NETWORKING_WSLAY_STRING_DATE_PARAM_NAME "=" );

    if( writtenLength < 0 )
    {
        ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
    }
    else if( writtenLength == *pBufferLength )
    {
        ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
    }
    else
    {
        *ppBuffer += writtenLength;
        *pBufferLength -= writtenLength;
    }

    /* X-Amz-Date value (plaintext). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( *ppBuffer, *pBufferLength, "%.*s",
                                  ( int ) dateLength, pDate );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == *pBufferLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            /* Keep the pointer and pBufferLength for URI encoded. */
        }
    }

    /* X-Amz-Date value (URI encoded) */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        encodedLength = *pBufferLength - writtenLength;
        ret = uriEncodedString( *ppBuffer, writtenLength, *ppBuffer + writtenLength, &encodedLength );

        /* Move and update pointer/remain length. */
        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            memmove( *ppBuffer, *ppBuffer + writtenLength, encodedLength );
            *ppBuffer += encodedLength;
            *pBufferLength -= encodedLength;
        }
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedExpires( char **ppBuffer, size_t *pBufferLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;
    size_t encodedLength;

    /* X-Amz-Expires query parameter. */
    writtenLength = snprintf( *ppBuffer, *pBufferLength, "&" NETWORKING_WSLAY_STRING_EXPIRES_PARAM_NAME "=" );

    if( writtenLength < 0 )
    {
        ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
    }
    else if( writtenLength == *pBufferLength )
    {
        ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
    }
    else
    {
        *ppBuffer += writtenLength;
        *pBufferLength -= writtenLength;
    }

    /* X-Amz-Expires value (plaintext). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( *ppBuffer, *pBufferLength, "%d", NETWORKING_WSLAY_STATIC_CRED_EXPIRES_SECONDS );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == *pBufferLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            /* Keep the pointer and pBufferLength for URI encoded. */
        }
    }

    /* X-Amz-Expires value (URI encoded) */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        encodedLength = *pBufferLength - writtenLength;
        ret = uriEncodedString( *ppBuffer, writtenLength, *ppBuffer + writtenLength, &encodedLength );

        /* Move and update pointer/remain length. */
        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            memmove( *ppBuffer, *ppBuffer + writtenLength, encodedLength );
            *ppBuffer += encodedLength;
            *pBufferLength -= encodedLength;
        }
    }

    return ret;
}

static NetworkingWslayResult_t writeUriEncodedSignedHeaders( char **ppBuffer, size_t *pBufferLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int32_t writtenLength;

    /* X-Amz-SignedHeaders query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( *ppBuffer, *pBufferLength, "&" NETWORKING_WSLAY_STRING_SIGNED_HEADERS_PARAM_NAME "=" NETWORKING_WSLAY_STRING_SIGNED_HEADERS_VALUE );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == *pBufferLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            *ppBuffer += writtenLength;
            *pBufferLength -= writtenLength;
        }
    }

    return ret;
}

static WebsocketResult_t generateQueryParameters( const char *pUrl, size_t urlLength,
                                                  const char *pHost, size_t hostLength,
                                                  const char *pPath, size_t pathLength,
                                                  char *pOutput, size_t *pOutputLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    NetworkingUtilsResult_t retUtils;
    const char *pQueryStart;
    size_t queryLength;
    char *pChannelArnValue, *pEqual;
    size_t channelArnValueLength;
    char *pCurrentWrite = pOutput;
    size_t remainLength, uriEncodedStringLength;
    int32_t writtenLength;
    char dateBuffer[ NETWORKING_UTILS_TIME_BUFFER_LENGTH ];
    NetworkingUtilsCanonicalRequest_t canonicalRequest;
    char *pSig;
    size_t sigLength;

    if( pUrl == NULL || pHost == NULL || pPath == NULL || pOutput == NULL || pOutputLength == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        retUtils = NetworkingUtils_GetIso8601CurrentTime( dateBuffer, NETWORKING_UTILS_TIME_BUFFER_LENGTH );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to get current ISO8601 date") );
            ret = NETWORKING_WSLAY_RESULT_FAIL_GET_DATE;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        pQueryStart = pPath + pathLength + 1; // +1 to skip '?' mark.
        queryLength = pUrl + urlLength - pQueryStart;

        if( queryLength < strlen( NETWORKING_WSLAY_STRING_CHANNEL_ARN_PARAM_NAME ) || 
            strncmp( pQueryStart, NETWORKING_WSLAY_STRING_CHANNEL_ARN_PARAM_NAME, strlen( NETWORKING_WSLAY_STRING_CHANNEL_ARN_PARAM_NAME ) ) != 0 )
        {
            /* No channel ARN exist. */
            ret = NETWORKING_WSLAY_RESULT_UNEXPECTED_WEBSOCKET_URL;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        /* Parse existing query parameters. */
        pEqual = strchr( pQueryStart, '=' );
        if( pEqual == NULL )
        {
            /* No equal found, unexpected. */
            ret = NETWORKING_WSLAY_RESULT_UNEXPECTED_WEBSOCKET_URL;
        }
        else
        {
            pChannelArnValue = pEqual + 1;
            channelArnValueLength = pQueryStart + queryLength - pChannelArnValue;
        }
    }

    /* Append X-Amz-Algorithm, X-Amz-ChannelARN, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, and X-Amz-SignedHeaders first
     * to generate signature. Then append X-Amz-Signature after getting it from sigv4 API.
     *
     * Note that the order of query parameters is important. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        remainLength = *pOutputLength;

        ret = writeUriEncodedAlgorithm( &pCurrentWrite, &remainLength );
    }

    /* X-Amz-ChannelARN query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = writeUriEncodedChannelArn( &pCurrentWrite, &remainLength, pChannelArnValue, channelArnValueLength );
    }

    /* X-Amz-Credential query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = writeUriEncodedCredential( &pCurrentWrite, &remainLength, dateBuffer );
    }

    /* X-Amz-Date query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = writeUriEncodedDate( &pCurrentWrite, &remainLength, dateBuffer, NETWORKING_UTILS_TIME_BUFFER_LENGTH - 1 );
    }

    /* X-Amz-Expires query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = writeUriEncodedExpires( &pCurrentWrite, &remainLength );
    }

    /* X-Amz-SignedHeaders query parameter. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = writeUriEncodedSignedHeaders( &pCurrentWrite, &remainLength );
    }

    /* Follow https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html to create canonical headers.
     * Websocket Format: "host: kinesisvideo.us-west-2.amazonaws.com\r\n"
     *
     * Note that we re-use the parsed result in pAppendHeaders from Websocket_Connect(). */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        uriEncodedStringLength = ( *pOutputLength ) - remainLength;
        writtenLength = snprintf( pCurrentWrite, remainLength,
                                  "%s: %.*s\r\n", "host", ( int ) hostLength, pHost );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == remainLength )
        {
            ret = NETWORKING_WSLAY_RESULT_AUTH_BUFFER_TOO_SMALL;
        }
        else
        {
            /* Do nothing, Coverity happy. */
        }
    }

    /* Sign the HTTP request. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        memset( &canonicalRequest, 0, sizeof( canonicalRequest ) );
        canonicalRequest.verb = NETWORKING_UTILS_HTTP_VERB_GET;
        canonicalRequest.pPath = (char*) pPath;
        canonicalRequest.pathLength = pathLength;
        canonicalRequest.pCanonicalQueryString = pOutput;
        canonicalRequest.canonicalQueryStringLength = uriEncodedStringLength;
        canonicalRequest.pCanonicalHeaders = pCurrentWrite;
        canonicalRequest.canonicalHeadersLength = writtenLength;
        canonicalRequest.pPayload = NULL;
        canonicalRequest.payloadLength = 0;
        
        networkingWslayContext.sigv4AuthBufferLength = NETWORKING_META_BUFFER_LENGTH;
        retUtils = NetworkingUtils_GenrerateAuthorizationHeader( &canonicalRequest, &networkingWslayContext.sigv4Credential,
                                                                 networkingWslayContext.credentials.pRegion, networkingWslayContext.credentials.regionLength, dateBuffer,
                                                                 networkingWslayContext.sigv4AuthBuffer, &networkingWslayContext.sigv4AuthBufferLength,
                                                                 &pSig, &sigLength );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to generate authorization header, return=%d", retUtils) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_CONNECT;
        }
    }

    /* Append signature. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        writtenLength = snprintf( pCurrentWrite, remainLength, "&" NETWORKING_WSLAY_STRING_SIGNATURE_PARAM_NAME "=%.*s",
                                 ( int ) sigLength, pSig );

        if( writtenLength < 0 )
        {
            ret = NETWORKING_WSLAY_RESULT_FAIL_SNPRINTF;
        }
        else if( writtenLength == remainLength )
        {
            ret = NETWORKING_WSLAY_RESULT_QUERY_PARAM_BUFFER_TOO_SMALL;
        }
        else
        {
            remainLength -= writtenLength;
        }
    }
    
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        *pOutputLength = *pOutputLength - remainLength;
    }

    return ret;
}

static WebsocketResult_t addHeader( HTTPRequestHeaders_t *pxRequestHeaders,
                                    const char *pName, size_t nameLength,
                                    const char *pValue, size_t valueLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    HTTPStatus_t xHttpStatus = HTTPSuccess;

    if( pxRequestHeaders == NULL || pName == NULL )
    {
        LogError( ("Invalid input while adding header.") );
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        xHttpStatus = HTTPClient_AddHeader( pxRequestHeaders,
                                            pName,
                                            nameLength,
                                            pValue,
                                            valueLength );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add %.*s. Error=%s.",
                        (int) nameLength, pName,
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_HTTP_ADD;
        }
    }

    return ret;
}

static void GenerateRandomBytes( uint8_t *pBuffer, size_t bufferLength )
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if( mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0 )
    {
        mbedtls_ctr_drbg_random(&ctr_drbg, pBuffer, bufferLength);
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

static WebsocketResult_t GenerateWebSocketClientKey( char *pClientKey, size_t clientKeyLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    uint8_t randomBuffer[ NETWORKING_WSLAY_CLIENT_KEY_RANDOM_LENGTH ];
    uint32_t olen = 0;
    int retBase64;

    if( pClientKey == NULL || clientKeyLength < NETWORKING_WSLAY_CLIENT_KEY_LENGTH + 1 )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        GenerateRandomBytes( randomBuffer, NETWORKING_WSLAY_CLIENT_KEY_RANDOM_LENGTH );

        retBase64 = mbedtls_base64_encode( (uint8_t*) pClientKey, clientKeyLength, (void*) &olen, randomBuffer, NETWORKING_WSLAY_CLIENT_KEY_RANDOM_LENGTH );
        if( retBase64 != 0 )
        {
            LogError( ("Fail to base64 encode to generate client key, return=0x%x", retBase64) );

            ret = NETWORKING_WSLAY_RESULT_FAIL_BASE64_ENCODE;
        }
    }

    return ret;
}

static WebsocketResult_t GenerateAcceptKey( const char *pClientKey, size_t clientKeyLength, char *pOutAcceptKey, size_t outAcceptKeyLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    char tempBuffer[ clientKeyLength + NETWORKING_WSLAY_RFC6455_UUID_LENGTH ];
    uint8_t sha1Buffer[ NETWORKING_WSLAY_SHA1_LENGTH ];
    int retBase64;
    uint32_t olen = 0;

    if( pClientKey == NULL || pOutAcceptKey == NULL || outAcceptKeyLength < NETWORKING_WSLAY_ACCEPT_KEY_LENGTH + 1 )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        memset( tempBuffer, 0, sizeof( tempBuffer ) );
        memset( sha1Buffer, 0, sizeof( sha1Buffer ) );

        memcpy( tempBuffer, pClientKey, clientKeyLength );
        memcpy( tempBuffer + clientKeyLength, NETWORKING_WSLAY_STRING_RFC6455_UUID, NETWORKING_WSLAY_RFC6455_UUID_LENGTH );

        mbedtls_sha1( ( unsigned char * ) tempBuffer, clientKeyLength + NETWORKING_WSLAY_RFC6455_UUID_LENGTH, sha1Buffer );
        retBase64 = mbedtls_base64_encode( (uint8_t*) pOutAcceptKey, outAcceptKeyLength, (void*) &olen, sha1Buffer, NETWORKING_WSLAY_SHA1_LENGTH );

        if( retBase64 != 0 )
        {
            LogError( ("Fail to base64 encode to generate accept key, return=0x%x", retBase64) );

            ret = NETWORKING_WSLAY_RESULT_FAIL_BASE64_ENCODE;
        }
    }

    return ret;
}

static WebsocketResult_t AcceptClientKey( const char *pAcceptKey, size_t acceptKeyLength, const char *pClientKey, size_t clientKeyLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    char tempAcceptKey[ NETWORKING_WSLAY_ACCEPT_KEY_LENGTH + 1 ];
    // 

    if( pAcceptKey == NULL || pClientKey == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = GenerateAcceptKey( pClientKey, clientKeyLength, tempAcceptKey, NETWORKING_WSLAY_ACCEPT_KEY_LENGTH + 1 );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        if( memcmp( pAcceptKey, tempAcceptKey, acceptKeyLength ) != 0 )
        {
            LogError( ("The accept key in response is invalid, accept key(%d)=%.*s, expected accept key(%d)=%.*s",
                       acceptKeyLength, (int) acceptKeyLength, pAcceptKey,
                       NETWORKING_WSLAY_ACCEPT_KEY_LENGTH, NETWORKING_WSLAY_ACCEPT_KEY_LENGTH, tempAcceptKey ) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_VERIFY_ACCEPT_KEY;
        }
    }

    return ret;
}

static void ParsingConnectResponseHeader( void * pContext,
                                          const char * fieldLoc,
                                          size_t fieldLen,
                                          const char * valueLoc,
                                          size_t valueLen,
                                          uint16_t statusCode )
{
    NetworkingWslayConnectResponseContext_t *pConnectContext = ( NetworkingWslayConnectResponseContext_t* ) pContext;
    NetworkingWslayResult_t ret;

    LogDebug( ("statusCode=%u, field(%d)=%.*s, value(%d)=%.*s", statusCode,
               fieldLen, fieldLen, fieldLoc,
               valueLen, valueLen, valueLoc) );
    
    pConnectContext->statusCode = statusCode;
    if( strncmp( fieldLoc, "Connection", fieldLen ) == 0 )
    {
        if( strncmp( valueLoc, "upgrade", valueLen ) == 0 )
        {
            pConnectContext->headersParsed |= NETWORKING_WSLAY_HTTP_HEADER_CONNECTION;
        }
    }
    else if( strncmp( fieldLoc, "upgrade", fieldLen ) == 0 )
    {
        if( strncmp( valueLoc, "websocket", valueLen ) == 0 )
        {
            pConnectContext->headersParsed |= NETWORKING_WSLAY_HTTP_HEADER_UPGRADE;
        }
    }
    else if( strncmp( fieldLoc, "sec-websocket-accept", fieldLen ) == 0 )
    {
        /* Verify client key. */
        ret = AcceptClientKey( valueLoc, valueLen, pConnectContext->pClientKey, pConnectContext->clientKeyLength );
        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            pConnectContext->headersParsed |= NETWORKING_WSLAY_HTTP_HEADER_WEBSOCKET_ACCEPT;
        }
    }
    else
    {
        /* Ignore other headers. */
    }
}

static WebsocketResult_t InitializeWslayContext( void )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    struct wslay_event_callbacks callbacks = {
        wslay_recv_callback,    /* wslay_event_recv_callback */
        wslay_send_callback,    /* wslay_event_send_callback */
        wslay_genmask_callback, /* wslay_event_genmask_callback */
        NULL,                   /* wslay_event_on_frame_recv_start_callback */
        NULL,                   /* wslay_event_on_frame_recv_chunk_callback */
        NULL,                   /* wslay_event_on_frame_recv_end_callback */
        wslay_msg_recv_callback /* wslay_event_on_msg_recv_callback */
    };

    wslay_event_context_client_init( &networkingWslayContext.wslayContext, &callbacks, &networkingWslayContext );
    networkingWslayContext.lastPingTick = xTaskGetTickCount();

    return ret;
}

static WebsocketResult_t InitializeWakeUpSocket( void )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    uint32_t socketTimeoutMs = 1U;

    networkingWslayContext.socketWakeUp = socket( PF_INET, SOCK_DGRAM, 0 );
    if( networkingWslayContext.socketWakeUp < 0 )
    {
        LogError( ("Fail to create wake up socket") );
        ret = NETWORKING_WSLAY_RESULT_FAIL_CREATE_SOCKET;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        memset( &networkingWslayContext.socketWakeUpAddr, 0, sizeof( struct sockaddr_in ) );
        networkingWslayContext.socketWakeUpAddr.sin_family = AF_INET;
        networkingWslayContext.socketWakeUpAddr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
        networkingWslayContext.socketWakeUpAddr.sin_port = 0;

        if( bind( networkingWslayContext.socketWakeUp, (const struct sockaddr *)&networkingWslayContext.socketWakeUpAddr, sizeof( networkingWslayContext.socketWakeUpAddr ) ) < 0 )
        {
            LogError( ("Fail to bind wake up socket") );
            closesocket( networkingWslayContext.socketWakeUp );
            ret = NETWORKING_WSLAY_RESULT_FAIL_BIND_SOCKET;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        setsockopt( networkingWslayContext.socketWakeUp, SOL_SOCKET, SO_RCVTIMEO, &socketTimeoutMs, sizeof( socketTimeoutMs ) );
        setsockopt( networkingWslayContext.socketWakeUp, SOL_SOCKET, SO_SNDTIMEO, &socketTimeoutMs, sizeof( socketTimeoutMs ) );
    }

    return ret;
}

static WebsocketResult_t ReadWebsocketMessage( void )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int retWslay;

    if( wslay_event_get_read_enabled( networkingWslayContext.wslayContext ) == 1 )
    {
        retWslay = wslay_event_recv( networkingWslayContext.wslayContext );
        if( retWslay != 0 )
        {
            LogError( ("wslay_event_recv returns error 0x%X", retWslay) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_RECV;
        }
    }

    return ret;
}

static WebsocketResult_t SendWebsocketMessage( struct wslay_event_msg *pArg )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int retWslay;
    size_t prev = 0, mid = 0, last = 0;

    if( wslay_event_get_write_enabled( networkingWslayContext.wslayContext ) == 1 )
    {
        // send the message out immediately.
        prev = wslay_event_get_queued_msg_count( networkingWslayContext.wslayContext );
        retWslay = wslay_event_queue_msg( networkingWslayContext.wslayContext, pArg );
        if( retWslay != 0 )
        {
            LogError( ("Fail to enqueue new message.") );
            ret = NETWORKING_WSLAY_RESULT_FAIL_QUEUE;
        }

        if( ret == NETWORKING_WSLAY_RESULT_OK )
        {
            mid = wslay_event_get_queued_msg_count( networkingWslayContext.wslayContext );
            retWslay = wslay_event_send( networkingWslayContext.wslayContext );

            last = wslay_event_get_queued_msg_count( networkingWslayContext.wslayContext );

            if( retWslay != 0 )
            {
                LogInfo( ("Fail to send this message at this moment.") );
            }

            LogDebug( ("Monitor wslay send queue (%u, %u, %u)", prev, mid, last) );
        }
    }
    else
    {
        LogError( ("Get write enable fail.") );
        ret = NETWORKING_WSLAY_RESULT_FAIL_WRITE_ENABLE;
    }

    return ret;
}

static WebsocketResult_t SendWebsocketText( uint8_t *pMessage, size_t messageLength )
{
    struct wslay_event_msg arg;
    
    memset( &arg, 0, sizeof( struct wslay_event_msg ) );
    arg.opcode = WSLAY_TEXT_FRAME;
    arg.msg = pMessage;
    arg.msg_length = messageLength;

    return SendWebsocketMessage( &arg );
}

static void SendWebsocketPing( void )
{
    struct wslay_event_msg arg;

    memset( &arg, 0, sizeof( struct wslay_event_msg ) );
    arg.opcode = WSLAY_PING;
    arg.msg_length = 0;
    LogInfo( ("wss ping ==>") );
    ( void ) SendWebsocketMessage( &arg );
}

static void ClearWakeUpSocketEvents( void )
{
    char tempBuffer[ 32 ];
    struct sockaddr addr;
    socklen_t addrLength = sizeof( addr );
    int recvLength;

    while( ( recvLength = recvfrom( networkingWslayContext.socketWakeUp, tempBuffer, sizeof( tempBuffer ), 0,
                                    (struct sockaddr *) &addr, (socklen_t*)&addrLength ) ) > 0 )
    {
        LogDebug( ("Clear %d byte on wake up socket", recvLength) );
    }
}

static void TriggerWakeUpSocket( void )
{
    char ch = 'a';
    int writtenLength;

    writtenLength = sendto( networkingWslayContext.socketWakeUp, &ch, 1, 0,
                            (struct sockaddr *) &networkingWslayContext.socketWakeUpAddr, sizeof( networkingWslayContext.socketWakeUpAddr ) );
    LogDebug( ("Sent %d byte to wake up running websocket thread", writtenLength) );
    if( writtenLength < 0 )
    {
        LogError( ("Fail to trigger wake up socket.") );
    }
}

WebsocketResult_t Websocket_Init( void * pCredential, WebsocketMessageCallback_t rxCallback, void *pRxCallbackContext )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    NetworkingWslayCredentials_t *pNetworkingWslayCredentials = (NetworkingWslayCredentials_t *)pCredential;
    static uint8_t first = 0U;

    if( pCredential == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK && !first )
    {
        memcpy( &networkingWslayContext.credentials, pCredential, sizeof(NetworkingWslayCredentials_t) );
        networkingWslayContext.sigv4Credential.pAccessKeyId = pNetworkingWslayCredentials->pAccessKeyId;
        networkingWslayContext.sigv4Credential.accessKeyIdLen = pNetworkingWslayCredentials->accessKeyIdLength;
        networkingWslayContext.sigv4Credential.pSecretAccessKey = pNetworkingWslayCredentials->pSecretAccessKey;
        networkingWslayContext.sigv4Credential.secretAccessKeyLen = pNetworkingWslayCredentials->secretAccessKeyLength;

        if( networkingWslayContext.credentials.userAgentLength > NETWORKING_WSLAY_USER_AGENT_NAME_MAX_LENGTH )
        {
            ret = NETWORKING_WSLAY_RESULT_USER_AGENT_NAME_LENGTH_TOO_LONG;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK && !first )
    {
        memset( &networkingWslayContext.xTransportInterface, 0, sizeof(TransportInterface_t) );
        memset( &networkingWslayContext.xNetworkContext, 0, sizeof(NetworkContext_t) );
        memset( &networkingWslayContext.xTlsTransportParams, 0, sizeof(TlsTransportParams_t) );
        
        /* Set transport interface. */
        networkingWslayContext.xTransportInterface.pNetworkContext = &networkingWslayContext.xNetworkContext;
        networkingWslayContext.xTransportInterface.send = TLS_FreeRTOS_send;
        networkingWslayContext.xTransportInterface.recv = TLS_FreeRTOS_recv;
        
        /* Set the pParams member of the network context with desired transport. */
        networkingWslayContext.xNetworkContext.pParams = &networkingWslayContext.xTlsTransportParams;

        networkingWslayContext.websocketRxCallback = rxCallback;
        networkingWslayContext.pWebsocketRxCallbackContext = pRxCallbackContext;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK && !first )
    {
        first = 1U;
    }

    return ret;
}

WebsocketResult_t Websocket_Connect( WebsocketServerInfo_t * pServerInfo )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    NetworkCredentials_t credentials;
    NetworkingUtilsResult_t retUtils;
    char *pHost, *pPath;
    size_t hostLength, pathLength;
    char host[ NETWORKING_WSLAY_HOST_NAME_MAX_LENGTH ];
    HTTPStatus_t xHttpStatus = HTTPSuccess;
    HTTPRequestHeaders_t xRequestHeaders = { 0 };
    HTTPRequestInfo_t xRequestInfo = { 0 };
    size_t queryParamsStringLength = NETWORKING_META_BUFFER_LENGTH;
    char clientKey[ NETWORKING_WSLAY_CLIENT_KEY_LENGTH + 1 ];
    HTTPResponse_t corehttpResponse;
    NetworkingWslayConnectResponseContext_t connectResponseContext;
    HTTPClient_ResponseHeaderParsingCallback_t headerParsingCallback = {
        .onHeaderCallback = ParsingConnectResponseHeader,
        .pContext = &connectResponseContext
    };
    
    if( pServerInfo == NULL || pServerInfo->pUrl == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        /* Get host pointer & length */
        retUtils = NetworkingUtils_GetUrlHost( pServerInfo->pUrl, pServerInfo->urlLength, &pHost, &hostLength );

        if( retUtils == NETWORKING_UTILS_RESULT_OK && hostLength < NETWORKING_WSLAY_HOST_NAME_MAX_LENGTH )
        {
            memcpy( host, pHost, hostLength );
            host[ hostLength ] = '\0';
        }
        else
        {
            LogError( ("Fail to find valid host name from URL: %.*s", (int) pServerInfo->urlLength, pServerInfo->pUrl) );
            ret = NETWORKING_WSLAY_RESULT_NO_HOST_IN_URL;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = NetworkingUtils_GetPathFromUrl( pServerInfo->pUrl, pServerInfo->urlLength, &pPath, &pathLength );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to find valid path from URL: %.*s", (int) pServerInfo->urlLength, pServerInfo->pUrl) );
            ret = NETWORKING_WSLAY_RESULT_NO_PATH_IN_URL;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = GenerateWebSocketClientKey( clientKey, NETWORKING_WSLAY_CLIENT_KEY_LENGTH + 1 );
    }
    
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        memset( &credentials, 0, sizeof( NetworkCredentials_t ) );
        credentials.pRootCa = networkingWslayContext.credentials.pRootCa;
        credentials.rootCaSize = networkingWslayContext.credentials.rootCaSize;

        retUtils = NetworkingUtils_ConnectToServer( &networkingWslayContext.xNetworkContext,
                                                    host,
                                                    443,
                                                    &credentials,
                                                    NETWORKING_WSLAY_SEND_TIMEOUT_MS,
                                                    NETWORKING_WSLAY_RECV_TIMEOUT_MS );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to connect the host: %s:%u", host, 443U) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_CONNECT;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        /* Follow https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html to create query parameters. */
        ret = generateQueryParameters( pServerInfo->pUrl,
                                       pServerInfo->urlLength,
                                       pHost,
                                       hostLength,
                                       pPath,
                                       pathLength,
                                       networkingWslayContext.metaBuffer,
                                       &queryParamsStringLength );
    }

    /* Store query parameters into path buffer. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        networkingWslayContext.websocketTxBuffer[ 0 ] = '/';
        networkingWslayContext.websocketTxBuffer[ 1 ] = '?';
        memcpy( &networkingWslayContext.websocketTxBuffer[ 2 ], networkingWslayContext.metaBuffer, queryParamsStringLength );

        pPath = networkingWslayContext.websocketTxBuffer;
        pathLength = 2U + queryParamsStringLength;
    }

    /* Prepare HTTP request for websocket connection */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        /* Initialize Request header buffer. */
        xRequestHeaders.pBuffer = (uint8_t*) networkingWslayContext.websocketTxBuffer + pathLength;
        xRequestHeaders.bufferLen = NETWORKING_WEBSOCKET_BUFFER_LENGTH - pathLength;

        /* Set HTTP request parameters to get temporary AWS IoT credentials. */
        xRequestInfo.pMethod = HTTP_METHOD_GET;
        xRequestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
        xRequestInfo.pPath = pPath;
        xRequestInfo.pathLen = pathLength;
        xRequestInfo.pHost = pHost;
        xRequestInfo.hostLen = hostLength;
        xRequestInfo.reqFlags = HTTP_REQUEST_NO_USER_AGENT_FLAG;
        /* Note that host would be added to the header field by HTTPClient_InitializeRequestHeaders. */

        /* Initialize request headers. */
        xHttpStatus = HTTPClient_InitializeRequestHeaders( &xRequestHeaders, &xRequestInfo );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to initialize request headers: Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_HTTP_INIT_REQUEST_HEADER;
        }
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "Pragma",
                         strlen( "Pragma" ),
                         "no-cache",
                         strlen("no-cache") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "Cache-Control",
                         strlen( "Cache-Control" ),
                         "no-cache",
                         strlen("no-cache") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "upgrade",
                         strlen( "upgrade" ),
                         "WebSocket",
                         strlen("WebSocket") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "connection",
                         strlen( "connection" ),
                         "Upgrade",
                         strlen("Upgrade") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "Sec-WebSocket-Key",
                         strlen( "Sec-WebSocket-Key" ),
                         clientKey,
                         NETWORKING_WSLAY_CLIENT_KEY_LENGTH );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "Sec-WebSocket-Protocol",
                         strlen( "Sec-WebSocket-Protocol" ),
                         "wss",
                         strlen("wss") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = addHeader( &xRequestHeaders,
                         "Sec-WebSocket-Version",
                         strlen( "Sec-WebSocket-Version" ),
                         "13",
                         strlen("13") );
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        memset( &corehttpResponse, 0, sizeof( HTTPResponse_t ) );
        corehttpResponse.pBuffer = (uint8_t *) networkingWslayContext.websocketRxBuffer;
        corehttpResponse.bufferLen = NETWORKING_WEBSOCKET_BUFFER_LENGTH;
        corehttpResponse.pHeaderParsingCallback = &headerParsingCallback;

        memset( &connectResponseContext, 0, sizeof( NetworkingWslayConnectResponseContext_t ) );
        connectResponseContext.pClientKey = clientKey;
        connectResponseContext.clientKeyLength = NETWORKING_WSLAY_CLIENT_KEY_LENGTH;

        LogDebug( ( "Sending HTTP header: %.*s", ( int ) xRequestHeaders.headersLen, xRequestHeaders.pBuffer ) );

        /* Send the request to AWS IoT Credentials Provider to obtain temporary credentials
         * so that the demo application can access configured S3 bucket thereafter. */
        xHttpStatus = HTTPClient_Send( &networkingWslayContext.xTransportInterface,
                                       &xRequestHeaders,
                                       NULL,
                                       0U,
                                       &corehttpResponse,
                                       HTTP_SEND_DISABLE_CONTENT_LENGTH_FLAG );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to send HTTP POST request to %.*s for obtaining temporary credentials: Error=%s.",
                        (int) hostLength, pHost,
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_HTTP_SEND;
        }
        else
        {
            LogDebug( ( "Receiving HTTP headers(%d): %.*s", corehttpResponse.headersLen, ( int ) corehttpResponse.headersLen, corehttpResponse.pHeaders ) );
        }
    }

    /* Check verified result in context. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        if( ( connectResponseContext.headersParsed | NETWORKING_WSLAY_HTTP_HEADER_CONNECTION ) == 0 ||
            ( connectResponseContext.headersParsed | NETWORKING_WSLAY_HTTP_HEADER_UPGRADE ) == 0 ||
            ( connectResponseContext.headersParsed | NETWORKING_WSLAY_HTTP_HEADER_WEBSOCKET_ACCEPT ) == 0 )
        {
            LogError( ("No valid response received, headersParsed=0x%x", connectResponseContext.headersParsed) );
            ret = NETWORKING_WSLAY_RESULT_FAIL_HTTP_PARSE_RESPONSE;
        }
        else
        {
            LogInfo( ("Successfully connect with WSS endpoint %.*s.",
                      (int) pServerInfo->urlLength, pServerInfo->pUrl ) );
        }
    }

    /* Initialize wslay context. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = InitializeWslayContext();
    }

    /* Initialize wake up socket for signal function. */
    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = InitializeWakeUpSocket();
    }

    return ret;
}

WebsocketResult_t Websocket_Send( char *pMessage, size_t messageLength )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;

    if( pMessage == NULL )
    {
        ret = NETWORKING_WSLAY_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        ret = SendWebsocketText( (uint8_t*) pMessage, messageLength );
    }

    return ret;
}

WebsocketResult_t Websocket_Recv( void )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;
    int fd = 0, maxFd = 0;
    fd_set rfds;
    struct timeval tv;
    int retSelect;
    TickType_t currentTick;

    fd = TLS_FreeRTOS_GetSocketFd( &networkingWslayContext.xNetworkContext );
    
    FD_ZERO( &rfds );
    FD_SET( fd, &rfds );
    FD_SET( networkingWslayContext.socketWakeUp, &rfds );
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    maxFd = fd > networkingWslayContext.socketWakeUp? fd:networkingWslayContext.socketWakeUp;

    retSelect = select( maxFd + 1, &rfds, NULL, NULL, &tv );
    if( retSelect < 0 )
    {
        LogError( ("select return error value %d", retSelect) );
        ret = NETWORKING_WSLAY_RESULT_FAIL_SELECT;
    }

    if( ret == NETWORKING_WSLAY_RESULT_OK )
    {
        if( FD_ISSET( fd, &rfds ) )
        {
            /* Have something to read. */
            ret = ReadWebsocketMessage();
        }
        
        if( FD_ISSET( networkingWslayContext.socketWakeUp, &rfds ) )
        {
            ClearWakeUpSocketEvents();
        }

        /* Handle ping interval. */
        currentTick = xTaskGetTickCount();
        if( currentTick - networkingWslayContext.lastPingTick >= NETWORKING_WSLAY_PING_PONG_INTERVAL_TICKS )
        {
            SendWebsocketPing();
            networkingWslayContext.lastPingTick = currentTick;
        }
    }

    return ret;
}

WebsocketResult_t Websocket_Signal( void )
{
    NetworkingWslayResult_t ret = NETWORKING_WSLAY_RESULT_OK;

    TriggerWakeUpSocket();

    return ret;
}
