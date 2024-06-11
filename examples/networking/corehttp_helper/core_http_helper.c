#include <time.h>

#include "FreeRTOS_POSIX/time.h"
#include "logging.h"
#include "core_http_helper.h"
#include "core_http_client.h"

#include "mbedtls/ssl.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/version.h"

#define NETWORKING_COREHTTP_SEND_TIMEOUT_MS ( 1000 )
#define NETWORKING_COREHTTP_RECV_TIMEOUT_MS ( 1000 )
#define NETWORKING_COREHTTP_USER_AGENT_NAME_MAX_LENGTH ( 128 )
#define NETWORKING_COREHTTP_STRING_SCHEMA_DELIMITER "://"
#define NETWORKING_COREHTTP_STRING_HOST "host"
#define NETWORKING_COREHTTP_STRING_USER_AGENT "user-agent"
#define NETWORKING_COREHTTP_STRING_AUTHORIZATION "Authorization"
#define NETWORKING_COREHTTP_STRING_CONTENT_TYPE "content-type"
#define NETWORKING_COREHTTP_STRING_CONTENT_TYPE_VALUE "application/json"
#define NETWORKING_COREHTTP_STRING_CONTENT_LENGTH "content-length"

static int32_t sha256Init( void * hashContext );
static int32_t sha256Update( void * hashContext,
                             const uint8_t * pInput,
                             size_t inputLen );
static int32_t sha256Final( void * hashContext,
                            uint8_t * pOutput,
                            size_t outputLen );

NetworkingCorehttpContext_t networkingCorehttpContext;

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
    .pRegion          = NETWORKING_COREHTTP_DEFAULT_REGION,
    .regionLen        = sizeof( NETWORKING_COREHTTP_DEFAULT_REGION ) - 1,
    .pService         = NETWORKING_COREHTTP_KVS_SERVICE_NAME,
    .serviceLen       = sizeof( NETWORKING_COREHTTP_KVS_SERVICE_NAME ) - 1,
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
}

static int32_t sha256Final( void * hashContext,
                            uint8_t * pOutput,
                            size_t outputLen )
{
    configASSERT( outputLen >= 32 );

    ( void ) outputLen;

    mbedtls_sha256_finish( hashContext, pOutput );
}

NetworkingCorehttpResult_t getUrlHost( char *pUrl, size_t urlLength, char **ppStart, size_t *pHostLength )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    char *pStart = NULL, *pEnd = pUrl + urlLength, *pCurPtr;
    uint8_t foundEndMark = 0;

    if( pUrl == NULL || ppStart == NULL || pHostLength == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        // Start from the schema delimiter
        pStart = strstr(pUrl, NETWORKING_COREHTTP_STRING_SCHEMA_DELIMITER);
        if( pStart == NULL )
        {
            ret = NETWORKING_COREHTTP_RESULT_SCHEMA_DELIMITER_NOT_FOUND;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        // Advance the pStart past the delimiter
        pStart += strlen( NETWORKING_COREHTTP_STRING_SCHEMA_DELIMITER );

        if( pStart > pEnd )
        {
            ret = NETWORKING_COREHTTP_RESULT_EXCEED_URL_LENGTH;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
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

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        *ppStart = pStart;
        *pHostLength = pCurPtr - pStart;
    }

    return ret;
}

NetworkingCorehttpResult_t getPathFromUrl( char *pUrl, size_t urlLength, char **ppPath, size_t *pPathLength )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    char *pHost, *pPathEnd;
    size_t hostLength;
    char *pStart;

    if( pUrl == NULL || ppPath == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Get host pointer & length */
        ret = getUrlHost( pUrl, urlLength, &pHost, &hostLength );
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
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

NetworkingCorehttpResult_t genrerateAuthorizationHeader( NetworkingCorehttpCanonicalRequest_t *pCanonicalRequest, char *pDate )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    SigV4HttpParameters_t sigv4HttpParams;
    SigV4Status_t sigv4Status = SigV4Success;
    /* Store Signature used in AWS HTTP requests generated using SigV4 library. */
    char * pcSignature = NULL;
    size_t xSignatureLen = 0;

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Setup the HTTP parameters for SigV4. */
        sigv4HttpParams.flags = 0;
        if( 1 )
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
        sigv4Params.pRegion = networkingCorehttpContext.credentials.pRegion;
        sigv4Params.regionLen = networkingCorehttpContext.credentials.regionLength;
        sigv4Params.pCredentials = &networkingCorehttpContext.sigv4Credential;
        sigv4Params.pDateIso8601 = pDate;

        /* Reset buffer length then generate authorization. */
        networkingCorehttpContext.sigv4AuthBufferLength = NETWORKING_COREHTTP_SIGV4_METADATA_BUFFER_LENGTH;
        sigv4Status = SigV4_GenerateHTTPAuthorization( &sigv4Params, networkingCorehttpContext.sigv4AuthBuffer, &networkingCorehttpContext.sigv4AuthBufferLength,
                                                       &pcSignature, &xSignatureLen );
        
        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Fail to generate HTTP authorization with return 0x%x", sigv4Status ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_SIGV4_GENERATE_AUTH;
        }
    }

    return ret;
}

static void getHeaderStartLocFromHttpRequest( HTTPRequestHeaders_t * pxRequestHeaders,
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

static NetworkingCorehttpResult_t connectToServer( NetworkContext_t * pxNetworkContext,
                                                   const char * pcServer,
                                                   NetworkCredentials_t * pxNetworkCredentials )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    TlsTransportStatus_t xNetworkStatus;

    if( pxNetworkContext == NULL || pcServer == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        LogInfo( ( "Establishing a TLS session with %s:%d.",
                   pcServer,
                   443 ) );

        /* Attempt to create a server-authenticated TLS connection. */
        xNetworkStatus = TLS_FreeRTOS_Connect( pxNetworkContext,
                                               pcServer,
                                               443,
                                               pxNetworkCredentials,
                                               NETWORKING_COREHTTP_SEND_TIMEOUT_MS,
                                               NETWORKING_COREHTTP_RECV_TIMEOUT_MS );
        
        if( xNetworkStatus != TLS_TRANSPORT_SUCCESS )
        {
            LogWarn( ("Fail to connect with server with return %d", xNetworkStatus) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_CONNECT;
        }
    }

    return ret;
}

NetworkingCorehttpResult_t getIso8601CurrentTime( char **ppDate, size_t * pDateLength )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    static char iso8601TimeBuf[ NETWORKING_COREHTTP_TIME_LENGTH ] = { 0 };
    struct timespec nowTime;
    time_t timeT;
    size_t timeLength = 0;

    if( ppDate == NULL || pDateLength == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        clock_gettime(CLOCK_REALTIME, &nowTime);
        timeT = nowTime.tv_sec;

        timeLength = strftime(iso8601TimeBuf, NETWORKING_COREHTTP_TIME_LENGTH, "%Y%m%dT%H%M%SZ", gmtime(&timeT));

        if( timeLength <= 0 )
        {
            LogError( ( "Fail to get time, timeLength=0x%x", timeLength ) );
            ret = NETWORKING_COREHTTP_RESULT_TIME_BUFFER_TOO_SMALL;
        }
    }
    
    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        *ppDate = iso8601TimeBuf;
        *pDateLength = timeLength;
        iso8601TimeBuf[ timeLength ] = '\0';
    }

    return ret;
}

HttpResult_t Http_Init( void * pCredential )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    NetworkingCorehttpCredentials_t *pNetworkingCorehttpCredentials = (NetworkingCorehttpCredentials_t *)pCredential;
    static uint8_t first = 0U;

    if( pCredential == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK && !first )
    {
        memcpy( &networkingCorehttpContext.credentials, pNetworkingCorehttpCredentials, sizeof(NetworkingCorehttpCredentials_t) );
        networkingCorehttpContext.sigv4Credential.pAccessKeyId = pNetworkingCorehttpCredentials->pAccessKeyId;
        networkingCorehttpContext.sigv4Credential.accessKeyIdLen = pNetworkingCorehttpCredentials->accessKeyIdLength;
        networkingCorehttpContext.sigv4Credential.pSecretAccessKey = pNetworkingCorehttpCredentials->pSecretAccessKey;
        networkingCorehttpContext.sigv4Credential.secretAccessKeyLen = pNetworkingCorehttpCredentials->secretAccessKeyLength;

        if( networkingCorehttpContext.credentials.userAgentLength > NETWORKING_COREHTTP_USER_AGENT_NAME_MAX_LENGTH )
        {
            ret = NETWORKING_COREHTTP_RESULT_USER_AGENT_NAME_TOO_LONG;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK && !first )
    {
        memset( &networkingCorehttpContext.xTransportInterface, 0, sizeof(TransportInterface_t) );
        memset( &networkingCorehttpContext.xNetworkContext, 0, sizeof(NetworkContext_t) );
        memset( &networkingCorehttpContext.xTlsTransportParams, 0, sizeof(TlsTransportParams_t) );
        
        /* Set transport interface. */
        networkingCorehttpContext.xTransportInterface.pNetworkContext = &networkingCorehttpContext.xNetworkContext;
        networkingCorehttpContext.xTransportInterface.send = TLS_FreeRTOS_send;
        networkingCorehttpContext.xTransportInterface.recv = TLS_FreeRTOS_recv;
        
        /* Set the pParams member of the network context with desired transport. */
        networkingCorehttpContext.xNetworkContext.pParams = &networkingCorehttpContext.xTlsTransportParams;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK && !first )
    {
        first = 1U;
    }
    
    return ret;
}

HttpResult_t Http_Send( HttpRequest_t *pRequest, size_t timeoutMs, HttpResponse_t *pResponse )
{
    NetworkingCorehttpResult_t ret = NETWORKING_COREHTTP_RESULT_OK;
    HTTPStatus_t xHttpStatus = HTTPSuccess;
    HTTPRequestHeaders_t xRequestHeaders = { 0 };
    HTTPRequestInfo_t xRequestInfo = { 0 };
    char * pDate = NULL;
    size_t dateLen;
    char *pPath;
    size_t pathLength;
    char *pHost;
    size_t hostLength;
    char contentLengthBuffer[ 11 ]; /* It needs 10 bytes for 32 bit integer, +1 for NULL terminator. */
    size_t contentLengthLength;
    /* Pointer to start of key-value pair buffer in request buffer. This is
     * used for Sigv4 signing */
    char * pcHeaderStart;
    size_t xHeadersLen;
    NetworkingCorehttpCanonicalRequest_t canonicalRequest;
    HTTPResponse_t corehttpResponse;
    NetworkCredentials_t credentials;
    
    if( pRequest == NULL || pResponse == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Get host pointer & length */
        ret = getUrlHost( pRequest->pUrl, pRequest->urlLength, &pHost, &hostLength );

        if( ret == NETWORKING_COREHTTP_RESULT_OK )
        {
            memcpy( networkingCorehttpContext.hostName, pHost, hostLength );
            networkingCorehttpContext.hostName[ hostLength ] = '\0';
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        ret = getPathFromUrl( pRequest->pUrl, pRequest->urlLength, &pPath, &pathLength );
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        memset( &credentials, 0, sizeof( NetworkCredentials_t ) );

        credentials.pRootCa = networkingCorehttpContext.credentials.pRootCa;
        credentials.rootCaSize = networkingCorehttpContext.credentials.rootCaSize;
        ret = connectToServer( &networkingCorehttpContext.xNetworkContext,
                               ( char * ) networkingCorehttpContext.hostName,
                               &credentials );
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Initialize Request header buffer. */
        xRequestHeaders.pBuffer = networkingCorehttpContext.requestBuffer;
        xRequestHeaders.bufferLen = NETWORKING_COREHTTP_BUFFER_LENGTH;

        /* Set HTTP request parameters to get temporary AWS IoT credentials. */
        xRequestInfo.pMethod = HTTP_METHOD_POST;
        xRequestInfo.methodLen = sizeof( HTTP_METHOD_POST ) - 1;
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
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_INIT_REQUEST_HEADER;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            NETWORKING_COREHTTP_STRING_USER_AGENT,
                                            strlen( NETWORKING_COREHTTP_STRING_USER_AGENT ),
                                            networkingCorehttpContext.credentials.pUserAgent,
                                            networkingCorehttpContext.credentials.userAgentLength );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add user-agent header to request headers: Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_USER_AGENT;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        ret = getIso8601CurrentTime( &pDate, &dateLen );
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            SIGV4_HTTP_X_AMZ_DATE_HEADER,
                                            strlen( SIGV4_HTTP_X_AMZ_DATE_HEADER ),
                                            pDate,
                                            dateLen );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add date header to request headers: Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_DATE;
        }
    }

    /* Sign the HTTP request. */
    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Find the start key-value pairs for sigv4 signing. */
        getHeaderStartLocFromHttpRequest( &xRequestHeaders, &pcHeaderStart, &xHeadersLen );

        memset( &canonicalRequest, 0, sizeof( canonicalRequest ) );
        canonicalRequest.pVerb = HTTP_METHOD_POST;
        canonicalRequest.pPath = pPath;
        canonicalRequest.pathLength = pathLength;
        canonicalRequest.pCanonicalQueryString = NULL;
        canonicalRequest.canonicalQueryStringLength = 0U;
        canonicalRequest.pCanonicalHeaders = pcHeaderStart;
        canonicalRequest.canonicalHeadersLength = xHeadersLen;
        canonicalRequest.pPayload = pRequest->pBody;
        canonicalRequest.payloadLength = pRequest->bodyLength;
        
        ret = genrerateAuthorizationHeader( &canonicalRequest, pDate );
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Add the authorization header to the HTTP request headers. */
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            NETWORKING_COREHTTP_STRING_AUTHORIZATION,
                                            strlen( NETWORKING_COREHTTP_STRING_AUTHORIZATION ),
                                            networkingCorehttpContext.sigv4AuthBuffer,
                                            networkingCorehttpContext.sigv4AuthBufferLength );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add Sigv4 auth header. Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_AUTH;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        contentLengthLength = snprintf( contentLengthBuffer, sizeof( contentLengthBuffer ), "%lu", pRequest->bodyLength );
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            NETWORKING_COREHTTP_STRING_CONTENT_LENGTH,
                                            strlen( NETWORKING_COREHTTP_STRING_CONTENT_LENGTH ),
                                            contentLengthBuffer,
                                            contentLengthLength );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add content type header to request headers: Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_CONTENT_TYPE;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            NETWORKING_COREHTTP_STRING_CONTENT_TYPE,
                                            strlen( NETWORKING_COREHTTP_STRING_CONTENT_TYPE ),
                                            NETWORKING_COREHTTP_STRING_CONTENT_TYPE_VALUE,
                                            strlen( NETWORKING_COREHTTP_STRING_CONTENT_TYPE_VALUE ) );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add content type header to request headers: Error=%s.",
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_ADD_HEADER_CONTENT_TYPE;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        memset( &corehttpResponse, 0, sizeof( HTTPResponse_t ) );
        corehttpResponse.pBuffer = (uint8_t *) pResponse->pBuffer;
        corehttpResponse.bufferLen = pResponse->bufferLength;
        corehttpResponse.pHeaderParsingCallback = NULL;

        LogDebug( ( "Sending HTTP header: %.*s", ( int ) xRequestHeaders.headersLen, xRequestHeaders.pBuffer ) );
        LogDebug( ( "Sending HTTP body: %.*s", ( int ) pRequest->bodyLength, pRequest->pBody ) );

        /* Send the request to AWS IoT Credentials Provider to obtain temporary credentials
         * so that the demo application can access configured S3 bucket thereafter. */
        xHttpStatus = HTTPClient_Send( &networkingCorehttpContext.xTransportInterface,
                                       &xRequestHeaders,
                                       (uint8_t *) pRequest->pBody,
                                       pRequest->bodyLength,
                                       &corehttpResponse,
                                       HTTP_SEND_DISABLE_CONTENT_LENGTH_FLAG );

        if( xHttpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to send HTTP POST request to %.*s for obtaining temporary credentials: Error=%s.",
                        (int) pRequest->urlLength, pRequest->pUrl,
                        HTTPClient_strerror( xHttpStatus ) ) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_HTTP_SEND;
        }
        else
        {
            LogDebug( ( "Receiving HTTP body(%d): %.*s", corehttpResponse.bodyLen, ( int ) corehttpResponse.bodyLen, corehttpResponse.pBody ) );

            /* Return the body part for signaling controller. */
            pResponse->bufferLength = corehttpResponse.bodyLen;
            pResponse->pBuffer = corehttpResponse.pBody;
        }
    }

    return ret;
}