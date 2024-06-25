#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include "logging.h"
#include "message_queue.h"

void MessageQueue_Destroy( MessageQueueHandler_t *pMessageQueueHandler, const char *pQueueName )
{
    if( pMessageQueueHandler != NULL )
    {
        vQueueDelete( pMessageQueueHandler->messageQueue );
    }
}

MessageQueueResult_t MessageQueue_Create( MessageQueueHandler_t *pMessageQueueHandler, const char *pQueueName, size_t messageMaxLength, size_t messageQueueMaxNum )
{
    MessageQueueResult_t ret = MESSAGE_QUEUE_RESULT_OK;

    if( pMessageQueueHandler == NULL || pQueueName == NULL )
    {
        ret = MESSAGE_QUEUE_RESULT_BAD_PARAMETER;
    }

    if( ret == MESSAGE_QUEUE_RESULT_OK )
    {
        pMessageQueueHandler->messageQueue = xQueueCreate( messageQueueMaxNum, messageMaxLength );

        if( pMessageQueueHandler->messageQueue == NULL )
        {
            ret = MESSAGE_QUEUE_RESULT_MQ_OPEN_FAILED;
        }
        else
        {
            pMessageQueueHandler->pQueueName = pQueueName;
            pMessageQueueHandler->messageMaxLength = messageMaxLength;
            pMessageQueueHandler->messageQueueMaxNum = messageQueueMaxNum;
        }
    }

    return ret;
}

MessageQueueResult_t MessageQueue_Send( MessageQueueHandler_t *pMessageQueueHandler, void *pMessage, size_t messageLength )
{
    MessageQueueResult_t ret = MESSAGE_QUEUE_RESULT_OK;
    BaseType_t retSend;

    if( pMessageQueueHandler == NULL || pMessage == NULL || messageLength != pMessageQueueHandler->messageMaxLength )
    {
        ret = MESSAGE_QUEUE_RESULT_BAD_PARAMETER;
    }

    if( ret == MESSAGE_QUEUE_RESULT_OK )
    {
        retSend = xQueueSend( pMessageQueueHandler->messageQueue, pMessage, 0 );
        if( retSend != pdTRUE )
        {
            LogError( ( "xQueueSend returns failed" ) );
            ret = MESSAGE_QUEUE_RESULT_MQ_SEND_FAILED;
        }
    }

    return ret;
}

MessageQueueResult_t MessageQueue_Recv( MessageQueueHandler_t *pMessageQueueHandler, void *pMessage, size_t *pMessageLength )
{
    MessageQueueResult_t ret = MESSAGE_QUEUE_RESULT_OK;
    BaseType_t retRecv;

    if( pMessageQueueHandler == NULL || pMessage == NULL || *pMessageLength < pMessageQueueHandler->messageMaxLength )
    {
        ret = MESSAGE_QUEUE_RESULT_BAD_PARAMETER;
    }

    if( ret == MESSAGE_QUEUE_RESULT_OK )
    {
        /* Infinite waiting. */
        retRecv = xQueueReceive( pMessageQueueHandler->messageQueue, pMessage, portMAX_DELAY );
        if( retRecv != pdTRUE )
        {
            LogError( ( "mq_receive returns failed" ) );
            ret = MESSAGE_QUEUE_RESULT_MQ_RECV_FAILED;
        }
    }

    if( ret == MESSAGE_QUEUE_RESULT_OK )
    {
        *pMessageLength = pMessageQueueHandler->messageMaxLength;
    }

    return ret;
}

MessageQueueResult_t MessageQueue_IsEmpty( MessageQueueHandler_t *pMessageQueueHandler )
{
    MessageQueueResult_t ret = MESSAGE_QUEUE_RESULT_OK;
    UBaseType_t pendingMessageNumber;

    if( pMessageQueueHandler == NULL )
    {
        ret = MESSAGE_QUEUE_RESULT_BAD_PARAMETER;
    }

    if( ret == MESSAGE_QUEUE_RESULT_OK )
    {
        pendingMessageNumber = uxQueueMessagesWaiting( pMessageQueueHandler->messageQueue );
        if( pendingMessageNumber == 0 )
        {
            ret = MESSAGE_QUEUE_RESULT_MQ_IS_EMPTY;
        }
        else
        {
            ret = MESSAGE_QUEUE_RESULT_MQ_HAVE_MESSAGE;
        }
    }

    return ret;
}
