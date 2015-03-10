/* 
 * Header for sine component in hipd 
 * Lingyuan He - 03/2015
 */

#ifndef _HIPD_SINE_H_
#define _HIPD_SINE_H_

#include <arpa/inet.h>
#include "libhipl/hidb.h"

pthread_mutex_t pref_mutex; /* mutex for setting preference */
char lsiaddr[INET_ADDRSTRLEN]; /* hip lsi address */

void *hip_pref_listener(void *);
void hip_sine_cleanup(void);
void hip_sine_init(void);
void hip_handoff(sockaddr_list *);
char* get_router_str(const char *);

#endif
