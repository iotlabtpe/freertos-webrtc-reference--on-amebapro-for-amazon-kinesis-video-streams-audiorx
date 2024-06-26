#include "logging.h"
#include "ice_controller.h"
#include "ice_controller_private.h"
#include "task.h"

#define ICE_CONTROLLER_SOCKET_LISTENER_QUEUE_NAME "/WebrtcApplicationIceControllerSocketListener"
#define MAX_QUEUE_MSG_NUM ( 10 )
#define ICE_CONTROLLER_SOCKET_LISTENER_SELECT_BLOCK_TIME_MS ( 50 )

static void pollingSockets( IceControllerContext_t *pCtx )
{
    fd_set rfds;
    int i;
    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = ICE_CONTROLLER_SOCKET_LISTENER_SELECT_BLOCK_TIME_MS * 1000,
    };
    int maxFd = 0;
    int retSelect;
    uint8_t skipProcess = 0;
    
    FD_ZERO( &rfds );

    if( xSemaphoreTake( pCtx->socketListenerContext.socketListenerMutex, portMAX_DELAY ) == pdTRUE )
    {
        for( i=0 ; i<pCtx->socketListenerContext.fdsCount ; i++ )
        {
            /* fds might be removed for any reason. Handle that by checking if it's -1. */
            if( pCtx->socketListenerContext.fds[i] != -1 )
            {
                FD_SET( pCtx->socketListenerContext.fds[i], &rfds );
                if( pCtx->socketListenerContext.fds[i] > maxFd )
                {
                    maxFd = pCtx->socketListenerContext.fds[i];
                }
            }
        }

        /* We have finished accessing the shared resource.  Release the mutex. */
        xSemaphoreGive( pCtx->socketListenerContext.socketListenerMutex );
    }
    else
    {
        LogError( ("Unexpected behavior: fail to take mutex") );
        skipProcess = 1;
    }
    
    if( skipProcess == 0 )
    {
        retSelect = select( maxFd + 1, &rfds, NULL, NULL, &tv );
        if( retSelect < 0 )
        {
            LogError( ("select return error value %d", retSelect) );
            skipProcess = 1;
        }
        else if( retSelect == 0 )
        {
            /* It's just timeout. */
            skipProcess = 1;
        }
        else
        {
            /* Empty else marker. */
        }
    }

    if( skipProcess == 0 )
    {
        for( i=0 ; i<pCtx->socketListenerContext.fdsCount ; i++ )
        {
            if( FD_ISSET( pCtx->socketListenerContext.fds[i], &rfds ) )
            {
                LogDebug( ("Detect packets on fd %d", pCtx->socketListenerContext.fds[i]) );
                (void) IceControllerNet_DetectRxPacket( pCtx, pCtx->socketListenerContext.pFdsMapContext[ i ] );
            }
        }
    }
}

IceControllerResult_t IceControllerSocketListener_AppendSocketHandler( IceControllerContext_t *pCtx, int socketFd, IceControllerSocketContext_t *pSocketContext )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    
    if( xSemaphoreTake( pCtx->socketListenerContext.socketListenerMutex, portMAX_DELAY ) == pdTRUE )
    {
        if( socketFd != -1 )
        {
            pCtx->socketListenerContext.fds[ pCtx->socketListenerContext.fdsCount ] = socketFd;
            pCtx->socketListenerContext.pFdsMapContext[ pCtx->socketListenerContext.fdsCount ] = pSocketContext;
            pCtx->socketListenerContext.fdsCount++;
        }

        /* We have finished accessing the shared resource.  Release the mutex. */
        xSemaphoreGive( pCtx->socketListenerContext.socketListenerMutex );
        
        LogDebug( ("Socket Listener: append socket handler %d", socketFd) );
    }
    else
    {
        LogError( ("Unexpected behavior: fail to take mutex") );
        ret = ICE_CONTROLLER_RESULT_FAIL_MUTEX_TAKE;
    }

    return ret;
}

IceControllerResult_t IceControllerSocketListener_RemoveSocketHandler( IceControllerContext_t *pCtx, int socketFd, IceControllerSocketContext_t *pSocketContext )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    int i;
    
    if( xSemaphoreTake( pCtx->socketListenerContext.socketListenerMutex, portMAX_DELAY ) == pdTRUE )
    {
        if( socketFd != -1 )
        {
            for( i=0 ; i<pCtx->socketListenerContext.fdsCount ; i++ )
            {
                if( socketFd == pCtx->socketListenerContext.fds[ i ] )
                {
                    pSocketContext->socketFd = -1;

                    if( i != pCtx->socketListenerContext.fdsCount - 1 )
                    {
                        /* If detaching handler is not the latest one, move all handlers ahead. */
                        memcpy( &pCtx->socketListenerContext.fds[ i ], &pCtx->socketListenerContext.fds[ i + 1 ], pCtx->socketListenerContext.fdsCount - 1 - i );
                        memcpy( &pCtx->socketListenerContext.pFdsMapContext[ i ], &pCtx->socketListenerContext.pFdsMapContext[ i + 1 ], pCtx->socketListenerContext.fdsCount - 1 - i );
                    }

                    /* Reset latest polling FD, counter, and mapped context. */
                    pCtx->socketListenerContext.fds[ i ] = -1;
                    pCtx->socketListenerContext.pFdsMapContext[ pCtx->socketListenerContext.fdsCount - 1 ] = NULL;
                    break;
                }
            }
        }

        /* We have finished accessing the shared resource.  Release the mutex. */
        xSemaphoreGive( pCtx->socketListenerContext.socketListenerMutex );
        
        LogDebug( ("Socket Listener: remove socket handler %d", socketFd) );
    }
    else
    {
        LogError( ("Unexpected behavior: fail to take mutex") );
        ret = ICE_CONTROLLER_RESULT_FAIL_MUTEX_TAKE;
    }

    return ret;
}

IceControllerResult_t IceControllerSocketListener_StartPolling( IceControllerContext_t *pCtx )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    
    if( xSemaphoreTake( pCtx->socketListenerContext.socketListenerMutex, portMAX_DELAY ) == pdTRUE )
    {
        pCtx->socketListenerContext.executeSocketListener = 1;

        /* We have finished accessing the shared resource.  Release the mutex. */
        xSemaphoreGive( pCtx->socketListenerContext.socketListenerMutex );
        
        LogDebug( ("Socket Listener: start polling") );
    }
    else
    {
        LogError( ("Unexpected behavior: fail to take mutex") );
        ret = ICE_CONTROLLER_RESULT_FAIL_MUTEX_TAKE;
    }

    return ret;
}

IceControllerResult_t IceControllerSocketListener_StopPolling( IceControllerContext_t *pCtx )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    
    if( xSemaphoreTake( pCtx->socketListenerContext.socketListenerMutex, portMAX_DELAY ) == pdTRUE )
    {
        pCtx->socketListenerContext.executeSocketListener = 0;

        /* We have finished accessing the shared resource.  Release the mutex. */
        xSemaphoreGive( pCtx->socketListenerContext.socketListenerMutex );
        
        LogDebug( ("Socket Listener: stop polling") );
    }
    else
    {
        LogError( ("Unexpected behavior: fail to take mutex") );
        ret = ICE_CONTROLLER_RESULT_FAIL_MUTEX_TAKE;
    }

    return ret;
}

IceControllerResult_t IceControllerSocketListener_InitializeTask( void *pParameter )
{
    IceControllerResult_t ret = ICE_CONTROLLER_RESULT_OK;
    IceControllerContext_t *pCtx = (IceControllerContext_t*) pParameter;
    int i;

    if( pCtx == NULL )
    {
        LogError( ("Invalid input: pCtx is NULL") );
        ret = ICE_CONTROLLER_RESULT_BAD_PARAMETER;
    }

    if( ret == ICE_CONTROLLER_RESULT_OK )
    {
        for( i=0 ; i<AWS_MAX_VIEWER_NUM * ICE_MAX_LOCAL_CANDIDATE_COUNT ; i++ )
        {
            pCtx->socketListenerContext.fds[i] = -1;
            pCtx->socketListenerContext.pFdsMapContext[i] = NULL;
        }

        pCtx->socketListenerContext.fdsCount = 0;
        pCtx->socketListenerContext.executeSocketListener = 0;
    }

    return ret;
}

void IceControllerSocketListener_Task( void *pParameter )
{
    IceControllerContext_t *pCtx = (IceControllerContext_t*) pParameter;

    /* Mutex can only be created in executing scheduler. */
    pCtx->socketListenerContext.socketListenerMutex = xSemaphoreCreateMutex();
    if( pCtx->socketListenerContext.socketListenerMutex == NULL )
    {
        configASSERT( pdFALSE );
        goto IDLE;
    }

    for( ;; )
    {
        while( pCtx->socketListenerContext.executeSocketListener == 0 )
        {
            vTaskDelay( pdMS_TO_TICKS( ICE_CONTROLLER_SOCKET_LISTENER_SELECT_BLOCK_TIME_MS ) );
        }

        if( pCtx->socketListenerContext.executeSocketListener == 1 )
        {
            pollingSockets( pCtx );
        }
    }

IDLE:
    for( ;; )
    {
        vTaskDelay( pdMS_TO_TICKS( 200 ) );
    }
}
