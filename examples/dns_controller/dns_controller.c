/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include "dns_controller.h"
#include "logging.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip_netconf.h"

#define DNS_CONTROLLER_MAX_MESSAGE_SIZE  sizeof( DnsRequest_t )
#define DNS_CONTROLLER_TASK_NAME         "DnsCtrler"
#define DNS_CONTROLLER_QUEUE_NAME        "DnsQueue"

/* DNS controller internal function prototypes */
static void DnsController_Task( void * pvParameters );
static DnsControllerResult_t DnsController_ProcessRequest( DnsControllerContext_t * pDnsCtx,
                                                           DnsRequest_t * pRequest );
static DnsControllerResult_t DnsController_PerformDnsLookup( DnsControllerContext_t * pDnsCtx,
                                                             const char * domainName,
                                                             DnsControllerIp_t * pIpAddress );

DnsControllerContext_t dnsContext;

/**
 * @brief DNS controller task function
 *
 * @param[in] pvParameters Task parameters (DNS controller context)
 */
static void DnsController_Task( void * pvParameters )
{
    DnsControllerResult_t ret = DNS_CONTROLLER_RESULT_OK;
    DnsControllerContext_t * pDnsCtx = &dnsContext;
    DnsRequest_t request;
    size_t messageLength = sizeof( DnsRequest_t );
    MessageQueueResult_t queueResult;

    ( void ) pvParameters;

    if( pDnsCtx == NULL )
    {
        LogError( ( "Invalid DNS controller context" ) );
        vTaskDelete( NULL );
        ret = DNS_CONTROLLER_RESULT_FAIL;
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        LogDebug( ( "DNS controller task started" ) );

        while( pDnsCtx->isRunning )
        {
            /* Wait for DNS requests from the queue */
            messageLength = sizeof( DnsRequest_t );
            queueResult = MessageQueue_Recv( &pDnsCtx->messageQueue, &request, &messageLength );

            if( queueResult != MESSAGE_QUEUE_RESULT_OK )
            {
                LogError( ( "Failed to receive DNS request from queue, error: %d", queueResult ) );
                continue;
            }

            /* Process the DNS request */
            ret = DnsController_ProcessRequest( pDnsCtx, &request );
        }
    }

    LogInfo( ( "DNS controller task exiting" ) );
    vTaskDelete( NULL );
}

/**
 * @brief Process a DNS request
 *
 * @param[in] pDnsCtx Pointer to the DNS controller context
 * @param[in] pRequest Pointer to the DNS request to process
 *
 * @return DNS_CONTROLLER_RESULT_OK if successful, otherwise an error code
 */
static DnsControllerResult_t DnsController_ProcessRequest( DnsControllerContext_t * pDnsCtx,
                                                           DnsRequest_t * pRequest )
{
    DnsControllerResult_t ret;
    DnsControllerIp_t ipAddress = {0};
    int i = 0;

    LogDebug( ( "Processing DNS request for domain: %s", pRequest->domainName ) );

    for( i = 0; i < pDnsCtx->maxRetries; i++ )
    {
        /* Perform DNS lookup */
        ret = DnsController_PerformDnsLookup( pDnsCtx, pRequest->domainName, &ipAddress );

        if( ret == DNS_CONTROLLER_RESULT_OK )
        {
            LogDebug( ( "DNS resolution successful for %s", pRequest->domainName ) );
            break;
        }
        else
        {
            LogError( ( "DNS resolution failed for %s, error: %d", pRequest->domainName, ret ) );
        }
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        /* If we have a callback, invoke it with the ret */
        if( pRequest->callbackFunc != NULL )
        {
            pRequest->callbackFunc( pRequest->pCustomContext, pRequest->requestId, &ipAddress, ret );
        }
        else
        {
            LogError( ( "DNS request with no callback function is not expected, target domain: %s", pRequest->domainName ) );
        }
    }

    return ret;
}

/**
 * @brief Perform a DNS lookup for a domain name
 *
 * @param[in] pDnsCtx Pointer to the DNS controller context
 * @param[in] domainName Domain name to resolve
 * @param[out] pIpAddress Pointer to store the resolved IP address
 *
 * @return DNS_CONTROLLER_RESULT_OK if successful, otherwise an error code
 */
static DnsControllerResult_t DnsController_PerformDnsLookup( DnsControllerContext_t * pDnsCtx,
                                                             const char * domainName,
                                                             DnsControllerIp_t * pIpAddress )
{
    DnsControllerResult_t ret = DNS_CONTROLLER_RESULT_OK;
    int dnsResult;
    struct addrinfo * pAddressInfos = NULL;
    struct addrinfo * pIterator = NULL;
    struct sockaddr_in * ipv4Address = NULL;
    // struct sockaddr_in6 * ipv6Address = NULL;
    struct addrinfo hints = { 0 };

    /* Restrict getaddrinfo to query IPv4 only. */
    memset( &hints, 0, sizeof( struct addrinfo ) );
    hints.ai_family = AF_INET;
    dnsResult = getaddrinfo( domainName, NULL, &hints, &pAddressInfos );
    if( dnsResult != 0 )
    {
        LogWarn( ( "DNS query failing, url: %s, result: %d", domainName, dnsResult ) );
        ret = DNS_CONTROLLER_RESULT_FAIL;
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        for( pIterator = pAddressInfos; pIterator; pIterator = pIterator->ai_next )
        {
            if( pIterator->ai_family == AF_INET )
            {
                ipv4Address = ( struct sockaddr_in * ) pIterator->ai_addr;
                pIpAddress->type = DNS_ADDRESS_TYPE_IPV4;
                memcpy( &pIpAddress->address.ipv4, &ipv4Address->sin_addr, sizeof( uint32_t ) );
                break;
            }
            else if( pIterator->ai_family == AF_INET6 )
            {
                /* TODO: IPv6. For now we don't support IPv6. */
                // ipv6Address = ( struct sockaddr_in6 * ) pIterator->ai_addr;
                // pIpAddress->type = DNS_ADDRESS_TYPE_IPV6;
                // memcpy( pIpAddress->address.ipv6, &ipv6Address->sin_addr, DNS_CONTROLLER_MAX_IP_LENGTH );
                // break;
                continue;
            }
        }

        if( pIterator == NULL )
        {
            ret = DNS_CONTROLLER_RESULT_FAIL;
        }
    }

    if( pAddressInfos != NULL )
    {
        freeaddrinfo( pAddressInfos );
    }

    return ret;
}

/**
 * @brief Initialize the DNS controller and its resources
 *
 * @return DNS_CONTROLLER_RESULT_OK if successful, otherwise an error code
 */
DnsControllerResult_t DnsController_Init( void )
{
    DnsControllerResult_t ret = DNS_CONTROLLER_RESULT_OK;
    DnsControllerContext_t * pDnsCtx = &dnsContext;
    MessageQueueResult_t queueResult;
    BaseType_t taskCreated = pdFALSE;

    if( pDnsCtx == NULL )
    {
        LogError( ( "Invalid DNS controller context" ) );
        ret = DNS_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    /* Initialize context */
    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        memset( pDnsCtx, 0, sizeof( DnsControllerContext_t ) );
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        /* Initialize message queue for DNS requests */
        queueResult = MessageQueue_Create( &pDnsCtx->messageQueue,
                                           DNS_CONTROLLER_QUEUE_NAME,
                                           DNS_CONTROLLER_MAX_MESSAGE_SIZE,
                                           DNS_CONTROLLER_QUEUE_LENGTH );
        if( queueResult != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Failed to create DNS controller message queue, error: %d", queueResult ) );
            ret = DNS_CONTROLLER_RESULT_FAIL;
        }
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        /* Initialize DNS controller context */
        pDnsCtx->maxRetries = DNS_CONTROLLER_MAX_RETRY_PER_REQUEST;

        /* Create the DNS task */
        taskCreated = xTaskCreate( DnsController_Task,
                                   DNS_CONTROLLER_TASK_NAME,
                                   DNS_CONTROLLER_STACK_SIZE,
                                   ( void * )pDnsCtx,
                                   DNS_CONTROLLER_PRIORITY,
                                   &pDnsCtx->taskHandle );
        if( taskCreated != pdPASS )
        {
            LogError( ( "Failed to create DNS task" ) );
            ret = DNS_CONTROLLER_RESULT_FAIL;
        }
        else
        {
            pDnsCtx->isRunning = 1;
        }
    }

    if( ret != DNS_CONTROLLER_RESULT_OK )
    {
        DnsController_Deinit();
    }

    return ret;
}

/**
 * @brief Deinitialize the DNS controller and free its resources
 *
 * @return void
 */
void DnsController_Deinit( void )
{
    DnsControllerContext_t * pDnsCtx = &dnsContext;

    /* Stop the task */
    if( pDnsCtx->taskHandle != NULL )
    {
        pDnsCtx->isRunning = 0;
        /* Give time for task to exit gracefully */
        vTaskDelay( pdMS_TO_TICKS( 100 ) );
        vTaskDelete( pDnsCtx->taskHandle );
        pDnsCtx->taskHandle = NULL;
    }

    /* Clean up message queue */
    MessageQueue_Destroy( &pDnsCtx->messageQueue, DNS_CONTROLLER_QUEUE_NAME );
}

/**
 * @brief Submit a DNS query to be processed by the DNS controller
 *
 * @param[in] pDnsCtx Pointer to the DNS controller context
 * @param[in] pRequest The DNS query request
 *
 * @return DNS_CONTROLLER_RESULT_OK if successful, otherwise an error code
 */
DnsControllerResult_t DnsController_SubmitQuery( DnsRequest_t * pRequest )
{
    DnsControllerResult_t ret = DNS_CONTROLLER_RESULT_OK;
    DnsControllerContext_t * pDnsCtx = &dnsContext;
    MessageQueueResult_t queueResult;

    if( pRequest == NULL )
    {
        LogError( ( "Invalid parameters, pRequest: %p", pRequest ) );
        ret = DNS_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        if( pDnsCtx->isRunning == 0U )
        {
            LogError( ( "DNS controller is not running" ) );
            ret = DNS_CONTROLLER_RESULT_FAIL;
        }
    }

    if( ret == DNS_CONTROLLER_RESULT_OK )
    {
        /* Submit request to queue */
        queueResult = MessageQueue_Send( &pDnsCtx->messageQueue, pRequest, sizeof( DnsRequest_t ) );
        if( queueResult != MESSAGE_QUEUE_RESULT_OK )
        {
            LogError( ( "Failed to send DNS request to queue, error: %d", queueResult ) );
            ret = DNS_CONTROLLER_RESULT_FAIL;
        }
    }

    return ret;
}