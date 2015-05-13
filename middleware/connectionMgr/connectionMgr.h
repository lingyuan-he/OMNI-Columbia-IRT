#ifndef _CONNECTION_MGR_H_
#define _CONNECTION_MGR_H_

#include <sys/socket.h>

enum connection_status {
   NEW,
   SEND,
   RECV,
   CONNECT,
   LISTEN,
   FIN
};

struct connection{
   int sockfd;
   int parent_sockfd;
   int app_guid;
   int policy_guid;
   enum connection_status status;
   socklen_t addrlen;
   const struct sockaddr *addr;
   struct connection *next;
};

void init_connection_tbl();
int update_connection_bind(int, const void *, int);
int update_connection_status(int, enum connection_status);
void add_connection(int, int);
void add_child_connection(int, int);
void print_connections();
char *convert_status(enum connection_status);
void update_last_connection(struct connection *);

#endif

