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

#ifndef DNS_CONTROLLER_H
#define DNS_CONTROLLER_H

#include <stdio.h>
#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "message_queue.h"

/* DNS Controller configuration */
#define DNS_CONTROLLER_STACK_SIZE        ( configMINIMAL_STACK_SIZE * 4 )
#define DNS_CONTROLLER_PRIORITY          ( tskIDLE_PRIORITY + 5 )
#define DNS_CONTROLLER_QUEUE_LENGTH      10
#define DNS_CONTROLLER_MAX_RETRY_PER_REQUEST      ( 3 )
#define DNS_CONTROLLER_MAX_TIMEOUT_SECOND_PER_QUERY     ( 10 )
#define DNS_CONTROLLER_MAX_IP_LENGTH              ( 0x10 )
#define DNS_CONTROLLER_MAX_DOMAIN_NAME_LENGTH     ( 256 )

typedef enum DnsControllerResult
{
    DNS_CONTROLLER_RESULT_OK = 0,
    DNS_CONTROLLER_RESULT_BAD_PARAMETER,
    DNS_CONTROLLER_RESULT_FAIL,
} DnsControllerResult_t;

typedef enum DnsControllerAddressType {
    DNS_ADDRESS_TYPE_NONE = 0,
    DNS_ADDRESS_TYPE_IPV4,
    DNS_ADDRESS_TYPE_IPV6,
} DnsControllerAddressType_t;

typedef struct DnsControllerIp
{
    DnsControllerAddressType_t type;                    // Indicates whether IPv4 or IPv6
    union
    {
        uint32_t ipv4;                                  // IPv4 address in network byte order
        uint8_t ipv6[ DNS_CONTROLLER_MAX_IP_LENGTH ];   // IPv6 address (16 bytes)
    } address;
} DnsControllerIp_t;

/* DNS task result callback type */
typedef void ( * DnsControllerResultCallback_t )( void * pCustomContext,
                                                  uint32_t requestId,
                                                  DnsControllerIp_t * pIp,
                                                  DnsControllerResult_t result );

// Structure to store DNS request details
typedef struct DnsRequest {
    uint32_t requestId;
    char domainName[ DNS_CONTROLLER_MAX_DOMAIN_NAME_LENGTH + 1 ]; // Domain name to be resolved
    DnsControllerResultCallback_t callbackFunc;
    void * pCustomContext;
} DnsRequest_t;

// DNS controller context structure
typedef struct DnsControllerContext
{
    TaskHandle_t taskHandle;            // FreeRTOS task handle
    MessageQueueHandler_t messageQueue; // Queue for DNS requests
    uint8_t isRunning;                  // Flag indicating if task is running
    uint8_t maxRetries;                 // Maximum number of retries per request
} DnsControllerContext_t;

/* DNS controller API */
DnsControllerResult_t DnsController_Init( void );
void DnsController_Deinit( void );
DnsControllerResult_t DnsController_SubmitQuery( DnsRequest_t * pRequest );

#endif /* DNS_CONTROLLER_H */
