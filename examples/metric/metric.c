#include "logging.h"
#include "metric.h"
#include "networking_utils.h"

#define METRIC_PRINT_INTERVAL_MS ( 10000 )

MetricContext_t context;

/* Convert event ID enum into string. */
static const char * ConvertEventToString( MetricEvent_t event );

/* Calculate the duration in miliseconds from start & end time. */
static uint64_t CalculateEventDurationMs( uint64_t startTimeUs,
                                          uint64_t endTimeUs );

/* The task to print metric regularly. */
static void Metric_Task( void * pParameter );

static const char * ConvertEventToString( MetricEvent_t event )
{
    const char * pRet = "Unknown";
    switch( event )
    {
        case METRIC_EVENT_NONE:
            pRet = "None";
            break;
        case METRIC_EVENT_SIGNALING_DESCRIBE_CHANNEL:
            pRet = "Describe Signaling Channel";
            break;
        case METRIC_EVENT_SIGNALING_GET_ENDPOINTS:
            pRet = "Get Signaling Endpoints";
            break;
        case METRIC_EVENT_SIGNALING_GET_ICE_SERVER_LIST:
            pRet = "Get Ice Server List";
            break;
        case METRIC_EVENT_SIGNALING_CONNECT_WSS_SERVER:
            pRet = "Connect Websocket Server";
            break;
        case METRIC_EVENT_ICE_GATHER_HOST_CANDIDATES:
            pRet = "Gather ICE Host Candidate";
            break;
        case METRIC_EVENT_ICE_GATHER_SRFLX_CANDIDATES:
            pRet = "Gather ICE Srflx Candidate";
            break;
        case METRIC_EVENT_ICE_FIND_P2P_CONNECTION:
            pRet = "Find Peer-To-Peer Connection";
            break;
        case METRIC_EVENT_PC_DTLS_HANDSHAKING:
            pRet = "DTLS Handshaking";
            break;
        case METRIC_EVENT_SENDING_FIRST_FRAME:
            pRet = "First Frame";
            break;
        default:
            pRet = "Unknown";
            break;
    }

    return pRet;
}

static uint64_t CalculateEventDurationMs( uint64_t startTimeUs,
                                          uint64_t endTimeUs )
{
    return ( endTimeUs - startTimeUs ) / 1000;
}

static void Metric_Task( void * pParameter )
{
    ( void ) pParameter;
    for( ;; )
    {
        Metric_PrintMetrics();

        vTaskDelay( pdMS_TO_TICKS( METRIC_PRINT_INTERVAL_MS ) );
    }
}

void Metric_Init( void )
{
    memset( &context, 0, sizeof( MetricContext_t ) );

    context.mutex = xSemaphoreCreateMutex();
    if( context.mutex == NULL )
    {
        LogError( ( "Fail to create mutex for Metric." ) );
    }
    else
    {
        context.isInit = 1U;
    }

    /* Create task for video Tx. */
    if( xTaskCreate( Metric_Task,
                     ( ( const char * )"MetricTask" ),
                     configMINIMAL_STACK_SIZE,
                     NULL,
                     tskIDLE_PRIORITY + 1,
                     NULL ) != pdPASS )
    {
        LogError( ( "xTaskCreate(MetricTask) failed" ) );
    }
}

void Metric_StartEvent( MetricEvent_t event )
{
    if( ( context.isInit == 1U ) && ( event < METRIC_EVENT_MAX ) &&
        ( xSemaphoreTake( context.mutex, portMAX_DELAY ) == pdTRUE ) )
    {
        MetricEventRecord_t * pEventRecord = &context.eventRecords[ event ];

        if( pEventRecord->state == METRIC_EVENT_STATE_NONE )
        {
            pEventRecord->state = METRIC_EVENT_STATE_RECORDING;
            pEventRecord->startTimeUs = NetworkingUtils_GetCurrentTimeUs( NULL );
        }

        xSemaphoreGive( context.mutex );
    }
}

void Metric_EndEvent( MetricEvent_t event )
{
    if( ( context.isInit == 1U ) && ( event < METRIC_EVENT_MAX ) &&
        ( xSemaphoreTake( context.mutex, portMAX_DELAY ) == pdTRUE ) )
    {
        MetricEventRecord_t * pEventRecord = &context.eventRecords[ event ];

        if( pEventRecord->state == METRIC_EVENT_STATE_RECORDING )
        {
            pEventRecord->state = METRIC_EVENT_STATE_RECORDED;
            pEventRecord->endTimeUs = NetworkingUtils_GetCurrentTimeUs( NULL );
        }

        xSemaphoreGive( context.mutex );
    }
}

void Metric_PrintMetrics( void )
{
    int i;
    MetricEventRecord_t * pEventRecord;
    static char runTimeStatsBuffer[ 4096 ];

    if( ( context.isInit == 1U ) &&
        ( xSemaphoreTake( context.mutex, portMAX_DELAY ) == pdTRUE ) )
    {
        LogInfo( ( "================================ Print Metrics Start ================================" ) );
        for( i = 0; i < METRIC_EVENT_MAX; i++ )
        {
            pEventRecord = &context.eventRecords[ i ];

            if( pEventRecord->state == METRIC_EVENT_STATE_RECORDED )
            {
                LogInfo( ( "Duration of %s: %llu ms",
                           ConvertEventToString( ( MetricEvent_t )i ),
                           CalculateEventDurationMs( pEventRecord->startTimeUs, pEventRecord->endTimeUs ) ) );
            }
        }

        LogInfo( ( "Remaining free heap size: %u", xPortGetFreeHeapSize() ) );

        vTaskGetRunTimeStats( runTimeStatsBuffer );
        LogInfo( ( " == Run Time Stat Start ==\n%s\n == Run Time Stat End ==", runTimeStatsBuffer ) );
        LogInfo( ( "================================ Print Metrics End ================================" ) );

        xSemaphoreGive( context.mutex );
    }
}
