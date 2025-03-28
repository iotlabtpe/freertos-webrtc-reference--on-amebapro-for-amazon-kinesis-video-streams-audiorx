#ifndef CORE_HTTP_CONFIG_H_
#define CORE_HTTP_CONFIG_H_

#include "logging.h"
#include "demo_config.h"

/* Logging configuration for the HTTP library. */
#ifndef LIBRARY_LOG_NAME
#define LIBRARY_LOG_NAME    "HTTP"
#endif

#ifndef LIBRARY_LOG_LEVEL
#define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

#define HTTP_USER_AGENT_VALUE AWS_KVS_AGENT_NAME

#endif /* ifndef CORE_HTTP_CONFIG_H_ */
