/* 
 * Header for omni component in hipd 
 * Lingyuan He - 03/2015
 */

#ifndef _HIPD_OMNI_H_
#define _HIPD_OMNI_H_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "libhipl/hidb.h"
#include <sys/socket.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define HIPD_OMNI_PORT 7776 /* port to listen */

//pthread_mutex_t hipd_omni_mutex; /* mutex for setting preference */
//char lsi_addr[INET_ADDRSTRLEN]; /* hip lsi address */
char hipd_omni_ifname[8]; /* current interface name */
int hipd_omni_socket; /* socket fd */

void hipd_omni_main(void); /* main function of the thread */
void hipd_omni_cleanup(int); /* cleanup when thread exits */
int hipd_omni_switch(const char *); /* switch to another interface */
char *hipd_omni_get_gateway(void); /* get gateway/router address by interface name */
char *hipd_omni_get_ifname(void); /* get current interface name */
void hipd_omni_update_ifname(void); /* update current interface name */
int hipd_omni_check_ifname(const char *); /* check if an interface exists */
int hipd_omni_is_ip_addr(const char *); /* check if a string is ip address */

#endif
