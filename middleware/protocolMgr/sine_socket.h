#ifndef _SINE_SOCKET_H_
#define _SINE_SOCKET_H_

#include <sys/types.h>

int sine_socket (int, int, int, int);
int sine_bind (int, const void *, int);
int sine_send(int, void *, int, int);
int sine_connect(int, void *, int);
int sine_getsockopt (int, int, int, void *, int *);
int sine_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int sine_shutdown(int, int);
int sine_close(int);
int sine_listen(int, int);
int sine_recv(int s, void *, int, int) ;
int sine_accept(int, void *, int *);
int sine_setsockopt(int, int, int, void *, int);
void sine_kill(void);
int sine_fcntl(int, int, int);
void init_policy_engine();

#endif

