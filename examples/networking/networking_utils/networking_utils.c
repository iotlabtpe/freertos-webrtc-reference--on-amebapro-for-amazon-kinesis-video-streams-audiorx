#include <time.h>

#include "FreeRTOS_POSIX/time.h"
#include "logging.h"
#include "networking_utils.h"

#include "mbedtls/ssl.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/version.h"

#define NETWORKING_UTILS_STRING_SCHEMA_DELIMITER "://"

static int32_t sha256Init( void * hashContext );
static int32_t sha256Update( void * hashContext,
                             const uint8_t * pInput,
                             size_t inputLen );
static int32_t sha256Final( void * hashContext,
                            uint8_t * pOutput,
                            size_t outputLen );

/**
 *  @brief mbedTLS Hash Context passed to SigV4 cryptointerface for generating the hash digest.
 */
static mbedtls_sha256_context xHashContext = { 0 };

/**
 * @brief CryptoInterface provided to SigV4 library for generating the hash digest.
 */
static SigV4CryptoInterface_t cryptoInterface =
{
    .hashInit      = sha256Init,
    .hashUpdate    = sha256Update,
    .hashFinal     = sha256Final,
    .pHashContext  = &xHashContext,
    .hashBlockLen  = 64,
    .hashDigestLen = 32,
};

static SigV4Parameters_t sigv4Params =
{
    .pCredentials     = NULL,
    .pDateIso8601     = NULL,
    .pRegion          = NULL,
    .regionLen        = 0,
    .pService         = NETWORKING_UTILS_KVS_SERVICE_NAME,
    .serviceLen       = strlen( NETWORKING_UTILS_KVS_SERVICE_NAME ),
    .pCryptoInterface = &cryptoInterface,
    .pHttpParameters  = NULL
};

static int32_t sha256Init( void * hashContext )
{
    mbedtls_sha256_init( ( mbedtls_sha256_context * ) hashContext );
    mbedtls_sha256_starts( hashContext, 0 );

    return 0;
}

static int32_t sha256Update( void * hashContext,
                             const uint8_t * pInput,
                             size_t inputLen )
{
    mbedtls_sha256_update( hashContext, pInput, inputLen );

    return 0;
}

static int32_t sha256Final( void * hashContext,
                            uint8_t * pOutput,
                            size_t outputLen )
{
    configASSERT( outputLen >= 32 );

    ( void ) outputLen;

    mbedtls_sha256_finish( hashContext, pOutput );

    return 0;
}

NetworkingUtilsResult_t NetworkingUtils_GetUrlHost( char *pUrl, size_t urlLength, char **ppStart, size_t *pHostLength )
{
    NetworkingUtilsResult_t ret = NETWORKING_UTILS_RESULT_OK;
    char *pStart = NULL, *pEnd = pUrl + urlLength, *pCurPtr;
    uint8_t foundEndMark = 0;

    if( pUrl == NULL || ppStart == NULL || pHostLength == NULL )
    {
        ret = NETWORKING_UTILS_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        // Start from the schema delimiter
        pStart = strstr(pUrl, NETWORKING_UTILS_STRING_SCHEMA_DELIMITER);
        if( pStart == NULL )
        {
            ret = NETWORKING_UTILS_RESULT_SCHEMA_DELIMITER_NOT_FOUND;
        }
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        // Advance the pStart past the delimiter
        pStart += strlen( NETWORKING_UTILS_STRING_SCHEMA_DELIMITER );

        if( pStart > pEnd )
        {
            ret = NETWORKING_UTILS_RESULT_INVALID_URL;
        }
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        // Find the delimiter which would indicate end of the host - either one of "/:?"
        pCurPtr = pStart;

        while( !foundEndMark && pCurPtr <= pEnd )
        {
            switch( *pCurPtr )
            {
                case '/':
                case ':':
                case '?':
                    foundEndMark = 1;
                    break;
                default:
                    pCurPtr++;
            }
        }
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        *ppStart = pStart;
        *pHostLength = pCurPtr - pStart;
    }

    return ret;
}

NetworkingUtilsResult_t NetworkingUtils_GetPathFromUrl( char *pUrl, size_t urlLength, char **ppPath, size_t *pPathLength )
{
    NetworkingUtilsResult_t ret = NETWORKING_UTILS_RESULT_OK;
    char *pHost, *pPathEnd;
    size_t hostLength;
    char *pStart;

    if( pUrl == NULL || ppPath == NULL )
    {
        ret = NETWORKING_UTILS_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        /* Get host pointer & length */
        ret = NetworkingUtils_GetUrlHost( pUrl, urlLength, &pHost, &hostLength );
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        /* Find '?' as end of path if any query parameters. */
        pStart = strchr( pHost + hostLength, '?' );

        if( pStart == NULL )
        {
            /* All the remaining part after the host belongs to the path. */
            pPathEnd = pUrl + urlLength;
            *ppPath = pHost + hostLength;
            *pPathLength = pPathEnd - *ppPath;
        }
        else
        {
            /* The part after the host until '?' belongs to the path. */
            pPathEnd = pStart;
            *ppPath = pHost + hostLength;
            *pPathLength = pPathEnd - *ppPath;
        }
    }

    return ret;
}

NetworkingUtilsResult_t NetworkingUtils_GenrerateAuthorizationHeader( NetworkingUtilsCanonicalRequest_t *pCanonicalRequest, SigV4Credentials_t *pSigv4Credential,
                                                                      const char *pAwsRegion, size_t awsRegionLength, const char *pDate, 
                                                                      char *pOutput, size_t *pOutputLength,
                                                                      char **ppOutSignature, size_t *pOutSignatureLength )
{
    NetworkingUtilsResult_t ret = NETWORKING_UTILS_RESULT_OK;
    SigV4HttpParameters_t sigv4HttpParams;
    SigV4Status_t sigv4Status = SigV4Success;
    
    if( pCanonicalRequest == NULL || pAwsRegion == NULL || pDate == NULL || pOutput == NULL || pOutputLength == NULL || ppOutSignature == NULL || pOutSignatureLength == NULL )
    {
        ret = NETWORKING_UTILS_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        /* Setup the HTTP parameters for SigV4. */
        sigv4HttpParams.flags = 0;
        if( pCanonicalRequest->verb == NETWORKING_UTILS_HTTP_VERB_POST )
        {
            sigv4HttpParams.pHttpMethod = HTTP_METHOD_POST;
            sigv4HttpParams.httpMethodLen = strlen( HTTP_METHOD_POST );
        }
        else
        {
            sigv4HttpParams.pHttpMethod = HTTP_METHOD_GET;
            sigv4HttpParams.httpMethodLen = strlen( HTTP_METHOD_GET );
            sigv4HttpParams.flags |= SIGV4_HTTP_QUERY_IS_CANONICAL_FLAG;
        }
        sigv4HttpParams.pPath = pCanonicalRequest->pPath;
        sigv4HttpParams.pathLen = pCanonicalRequest->pathLength;
        sigv4HttpParams.pQuery = pCanonicalRequest->pCanonicalQueryString;
        sigv4HttpParams.queryLen = pCanonicalRequest->canonicalQueryStringLength;
        sigv4HttpParams.pHeaders = pCanonicalRequest->pCanonicalHeaders;
        sigv4HttpParams.headersLen = pCanonicalRequest->canonicalHeadersLength;
        sigv4HttpParams.pPayload = pCanonicalRequest->pPayload;
        sigv4HttpParams.payloadLen = pCanonicalRequest->payloadLength;
        
        /* Initializing sigv4Params with Http parameters required for the HTTP request. */
        sigv4Params.pHttpParameters = &sigv4HttpParams;
        sigv4Params.pRegion = pAwsRegion;
        sigv4Params.regionLen = awsRegionLength;
        sigv4Params.pCredentials = pSigv4Credential;
        sigv4Params.pDateIso8601 = pDate;

        /* Reset buffer length then generate authorization. */
        sigv4Status = SigV4_GenerateHTTPAuthorization( &sigv4Params, pOutput, pOutputLength,
                                                       ppOutSignature, pOutSignatureLength );
        
        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Fail to generate HTTP authorization with return 0x%x", sigv4Status ) );
            ret = NETWORKING_UTILS_RESULT_FAIL_SIGV4_GENAUTH;
        }
    }

    return ret;
}

void NetworkingUtils_GetHeaderStartLocFromHttpRequest( HTTPRequestHeaders_t * pxRequestHeaders,
                                                       char ** pcStartHeaderLoc,
                                                       size_t * pxHeadersDataLen )
{
    size_t xHeaderLen = pxRequestHeaders->headersLen;
    char * pcHeaders = ( char * ) pxRequestHeaders->pBuffer;
    bool xNewLineFound = false;

    if( pxRequestHeaders != NULL && pcStartHeaderLoc != NULL && pxHeadersDataLen != NULL )
    {
        while( xHeaderLen >= 2 )
        {
            /* The request line ends in \r\n. Look for \r\n. */
            if( 0 == strncmp( pcHeaders, "\r\n", strlen( "\r\n" ) ) )
            {
                xNewLineFound = true;
                break;
            }

            pcHeaders++;
            xHeaderLen--;
        }

        if( xNewLineFound == false )
        {
            LogError( ( "Failed to find starting location of HTTP headers in HTTP request: \"\\r\\n\" missing before start of HTTP headers." ) );
            *pxHeadersDataLen = 0;
            *pcStartHeaderLoc = NULL;
        }
        else
        {
            /* Moving header pointer past "\r\n" .*/
            *pxHeadersDataLen = xHeaderLen - 2;
            *pcStartHeaderLoc = pcHeaders + 2;
        }
    }
}

NetworkingUtilsResult_t NetworkingUtils_ConnectToServer( NetworkContext_t * pxNetworkContext,
                                        const char * pcServer,
                                        uint16_t port,
                                        NetworkCredentials_t * pxNetworkCredentials,
                                        uint32_t sendTimeoutMs,
                                        uint32_t recvTimeoutMs )
{
    NetworkingUtilsResult_t ret = NETWORKING_UTILS_RESULT_OK;
    TlsTransportStatus_t xNetworkStatus;

    if( pxNetworkContext == NULL || pcServer == NULL )
    {
        ret = NETWORKING_UTILS_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        LogInfo( ( "Establishing a TLS session with %s:%d.",
                   pcServer,
                   port ) );

        /* Attempt to create a server-authenticated TLS connection. */
        xNetworkStatus = TLS_FreeRTOS_Connect( pxNetworkContext,
                                               pcServer,
                                               port,
                                               pxNetworkCredentials,
                                               sendTimeoutMs,
                                               recvTimeoutMs );
        
        if( xNetworkStatus != TLS_TRANSPORT_SUCCESS )
        {
            LogWarn( ("Fail to connect with server with return %d", xNetworkStatus) );
            ret = NETWORKING_UTILS_RESULT_FAIL_CONNECT;
        }
    }

    return ret;
}

NetworkingUtilsResult_t NetworkingUtils_GetIso8601CurrentTime( char *pDate, size_t dateBufferLength )
{
    NetworkingUtilsResult_t ret = NETWORKING_UTILS_RESULT_OK;
    struct timespec nowTime;
    time_t timeT;
    size_t timeLength = 0;

    if( pDate == NULL || dateBufferLength < NETWORKING_UTILS_TIME_BUFFER_LENGTH )
    {
        ret = NETWORKING_UTILS_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        clock_gettime(CLOCK_REALTIME, &nowTime);
        timeT = nowTime.tv_sec;

        timeLength = strftime(pDate, dateBufferLength, "%Y%m%dT%H%M%SZ", gmtime(&timeT));

        if( timeLength <= 0 )
        {
            LogError( ( "Fail to get time, timeLength=0x%x", timeLength ) );
            ret = NETWORKING_UTILS_RESULT_TIME_BUFFER_OUT_OF_MEMORY;
        }
    }
    
    if( ret == NETWORKING_UTILS_RESULT_OK )
    {
        pDate[ timeLength ] = '\0';
    }

    return ret;
}