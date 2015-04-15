# Unified Heterogeneous Networking Middleware
# Main Makefile

# commands
CD=cd
CP=cp
GCC=gcc
CPP=g++
BJAM=b2
SED=sed
TAR=tar
RM=rm
PWD=$(pwd)

# empty for linux compilation
TOOLSET=
LDFLAGS=
ANDROID=

all: socks hip mih additional

socks:
	$(MAKE) -C ./middleware

hip:
	$(MAKE) -C ./protocols/hip/hipl-1.0.8

mih:
	$(CD) ./protocols/mih/odtone-0.6; $(BJAM) --boost-root=../boost_1_48_0 linkflags=-lpthread

additional:
	$(CD) ./protocols/mih/; $(CD) dist; $(CP) -r * ../odtone-0.6/dist; $(CD) ../;

install:
	./middleware/kill_sined
	$(SED) 's/OMNI_ROOT=/OMNI_ROOT=$(subst /,\/,$(PWD))/' <./protocols/mih/mih >/usr/local/sbin/mih
	chmod +x /usr/local/sbin/mih
	$(CP) ./middleware/sine_policy.conf /etc/sine_policy.conf
	$(CP) ./middleware/srelay.conf /etc/srelay.conf
	$(CP) ./middleware/sined /usr/local/sbin/sined
	$(CP) ./middleware/kill_sined /usr/local/sbin/kill_sined
	$(CP) ./middleware/locsw /usr/local/sbin/locsw
	$(MAKE) install -C ./protocols/hip/hipl-1.0.8/

clean:
	$(MAKE) -C ./middleware clean
	$(MAKE) -C ./protocols/hip/hipl-1.0.8 clean
	$(CD) ./protocols/mih/odtone-0.6; $(BJAM) clean

