#ifndef CORE_HTTP_CONFIG_H_
#define CORE_HTTP_CONFIG_H_

#include "logging.h"

/* Logging configuration for the HTTP library. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME    "HTTP"
#endif

#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

#endif /* ifndef CORE_HTTP_CONFIG_H_ */
