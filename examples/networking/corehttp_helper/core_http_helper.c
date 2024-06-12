#include <time.h>

#include "FreeRTOS_POSIX/time.h"
#include "logging.h"
#include "core_http_helper.h"
#include "core_http_client.h"
#include "networking_utils.h"

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

NetworkingCorehttpContext_t networkingCorehttpContext;

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
    NetworkingUtilsResult_t retUtils;
    HTTPStatus_t xHttpStatus = HTTPSuccess;
    HTTPRequestHeaders_t xRequestHeaders = { 0 };
    HTTPRequestInfo_t xRequestInfo = { 0 };
    char dateBuffer[ NETWORKING_UTILS_TIME_BUFFER_LENGTH ];
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
    NetworkingUtilsCanonicalRequest_t canonicalRequest;
    HTTPResponse_t corehttpResponse;
    NetworkCredentials_t credentials;
    
    if( pRequest == NULL || pResponse == NULL )
    {
        ret = NETWORKING_COREHTTP_RESULT_BAD_PARAMETER;
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        /* Get host pointer & length */
        retUtils = NetworkingUtils_GetUrlHost( pRequest->pUrl, pRequest->urlLength, &pHost, &hostLength );

        if( retUtils == NETWORKING_UTILS_RESULT_OK )
        {
            memcpy( networkingCorehttpContext.hostName, pHost, hostLength );
            networkingCorehttpContext.hostName[ hostLength ] = '\0';
        }
        else
        {
            LogError( ("Fail to find valid host name from URL: %.*s", (int) pRequest->urlLength, pRequest->pUrl) );
            ret = NETWORKING_COREHTTP_RESULT_NO_HOST_IN_URL;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        ret = NetworkingUtils_GetPathFromUrl( pRequest->pUrl, pRequest->urlLength, &pPath, &pathLength );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to find valid path from URL: %.*s", (int) pRequest->urlLength, pRequest->pUrl) );
            ret = NETWORKING_COREHTTP_RESULT_NO_PATH_IN_URL;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        memset( &credentials, 0, sizeof( NetworkCredentials_t ) );
        credentials.pRootCa = networkingCorehttpContext.credentials.pRootCa;
        credentials.rootCaSize = networkingCorehttpContext.credentials.rootCaSize;

        retUtils = NetworkingUtils_ConnectToServer( &networkingCorehttpContext.xNetworkContext,
                                                    networkingCorehttpContext.hostName,
                                                    443,
                                                    &credentials,
                                                    NETWORKING_COREHTTP_SEND_TIMEOUT_MS,
                                                    NETWORKING_COREHTTP_RECV_TIMEOUT_MS );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to connect the host: %s:%u", networkingCorehttpContext.hostName, 443U) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_CONNECT;
        }
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
        retUtils = NetworkingUtils_GetIso8601CurrentTime( dateBuffer, NETWORKING_UTILS_TIME_BUFFER_LENGTH );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to get current ISO8601 date") );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_GET_DATE;
        }
    }

    if( ret == NETWORKING_COREHTTP_RESULT_OK )
    {
        xHttpStatus = HTTPClient_AddHeader( &xRequestHeaders,
                                            SIGV4_HTTP_X_AMZ_DATE_HEADER,
                                            strlen( SIGV4_HTTP_X_AMZ_DATE_HEADER ),
                                            dateBuffer,
                                            NETWORKING_UTILS_TIME_BUFFER_LENGTH - 1 );

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
        NetworkingUtils_GetHeaderStartLocFromHttpRequest( &xRequestHeaders, &pcHeaderStart, &xHeadersLen );

        memset( &canonicalRequest, 0, sizeof( canonicalRequest ) );
        canonicalRequest.verb = NETWORKING_UTILS_HTTP_VERB_POST;
        canonicalRequest.pPath = pPath;
        canonicalRequest.pathLength = pathLength;
        canonicalRequest.pCanonicalQueryString = NULL;
        canonicalRequest.canonicalQueryStringLength = 0U;
        canonicalRequest.pCanonicalHeaders = pcHeaderStart;
        canonicalRequest.canonicalHeadersLength = xHeadersLen;
        canonicalRequest.pPayload = pRequest->pBody;
        canonicalRequest.payloadLength = pRequest->bodyLength;
        
        networkingCorehttpContext.sigv4AuthBufferLength = NETWORKING_COREHTTP_SIGV4_METADATA_BUFFER_LENGTH;
        retUtils = NetworkingUtils_GenrerateAuthorizationHeader( &canonicalRequest, &networkingCorehttpContext.sigv4Credential,
                                                                 networkingCorehttpContext.credentials.pRegion, networkingCorehttpContext.credentials.regionLength, dateBuffer,
                                                                 networkingCorehttpContext.sigv4AuthBuffer, &networkingCorehttpContext.sigv4AuthBufferLength );

        if( retUtils != NETWORKING_UTILS_RESULT_OK )
        {
            LogError( ("Fail to generate authorization header, return=%d", retUtils) );
            ret = NETWORKING_COREHTTP_RESULT_FAIL_CONNECT;
        }
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
        contentLengthLength = snprintf( contentLengthBuffer, sizeof( contentLengthBuffer ), "%u", pRequest->bodyLength );
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
            pResponse->pBuffer = (char*) corehttpResponse.pBody;
        }
    }

    return ret;
}