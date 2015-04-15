# Unified Heterogeneous Networking Middleware
# Makefile for Middleware

# ANDROID and TOOLSET for compatibility in cross-compilation

TARGET = sined
MAKE = make
CC = $(TOOLSET)gcc
CXX = $(TOOLSET)g++
AR = $(TOOLSET)ar
LD = $(TOOLSET)ld

SRCS = ./protocolMgr/sine_socket.c ./connectionMgr/connectionMgr.c ./policyMgr/PolicyModel.cpp ./policyMgr/PolicyListener.cpp ./policyMgr/PolicyController.cpp ./networkMgr/nm.cpp ./locationMgr/lm.cpp ./securityMgr/sm.cpp ./srelay/srelay-0.4.8b5/config.h ./srelay/srelay-0.4.8b5/init.c ./srelay/srelay-0.4.8b5/readconf.c ./srelay/srelay-0.4.8b5/util.c ./srelay/srelay-0.4.8b5/socks.c ./srelay/srelay-0.4.8b5/relay.c ./srelay/srelay-0.4.8b5/main.c ./srelay/srelay-0.4.8b5/auth-pwd.c ./srelay/srelay-0.4.8b5/get-bind.c

OBJS = ./protocolMgr/sine_socket.o ./connectionMgr/connectionMgr.o ./policyMgr/PolicyModel.o ./policyMgr/PolicyListener.o ./policyMgr/PolicyController.o ./networkMgr/nm.o ./locationMgr/lm.o ./securityMgr/sm.o
OBJS	+= ./srelay/srelay-0.4.8b5/init.o ./srelay/srelay-0.4.8b5/readconf.o ./srelay/srelay-0.4.8b5/util.o ./srelay/srelay-0.4.8b5/get-bind.o ./srelay/srelay-0.4.8b5/socks.o ./srelay/srelay-0.4.8b5/relay.o ./srelay/srelay-0.4.8b5/main.o ./srelay/srelay-0.4.8b5/auth-pwd.o

CFLAGS = -shared -fPIC -O2 -DHAVE_CONFIG_H -g -DNDEBUG
#CFLAGS	+= -Dconnect=sine_connect -Dbind=sine_bind -Dgetsockname=sine_getsockname -Dgetpeername=sine_getpeername -Daccept=sine_accept -Drresvport=sine_rresvport -Dbindresvport=sine_bindresvport -Dgethostbyname=sine_gethostbyname -Dgethostbyname2=sine_gethostbyname2 -Dsendto=sine_sendto -Drecvfrom=sine_recvfrom -Drecvfrom=sine_recvfrom -Dwrite=sine_write -Dwritev=sine_writev -Dlisten=sine_listen -Dsend=sine_send -Dsendmsg=sine_sendmsg -Dread=sine_read -Dreadv=sine_readv -Drecv=sine_recv -Drecvmsg=sine_recvmsg -Dgetaddrinfo=sine_getaddrinfo -Dgetipnodebyname=sine_getipnodebyname

#WARN = -Wall -Wno-unused

CPPFLAGS = -I./protocolMgr -I./connectionMgr -I./policyMgr -I./networkMgr -I./locationMgr -I./srelay/srelay-0.4.8b5 $(ANDROID)

LIBS = -lpthread -lcrypt -lcurl -lwrap -lz -lssl -lcrypto

default: all

$(TARGET): $(OBJS)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

locsw: ./locationSwitch/locationSwitch.cpp
	$(CXX) $(CPPFLAGS) $(LDFLAGS) ./locationSwitch/locationSwitch.cpp -lpthread -o locsw

all: $(TARGET) locsw

clean:
	rm -f $(OBJS) $(TARGET) *_tcp_kern* *~ core
	rm -f ./locationSwitch/locationSwitch.o locsw

