#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <lwip/def.h>

#define htons(x) lwip_htons(x)
#define ntohs(x) lwip_ntohs(x)
#define htonl(x) lwip_htonl(x)
#define ntohl(x) lwip_ntohl(x)

#endif
