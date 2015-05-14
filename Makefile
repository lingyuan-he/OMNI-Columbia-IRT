# Unified Heterogeneous Networking Middleware
# Main Makefile

# current folder
PWD=$(shell pwd)

# commands
CD=cd
CP=cp
GCC=gcc
CPP=g++
SED=sed
TAR=tar
RM=rm
BJAM=$(PWD)/protocols/mih/boost_1_48_0/b2

# software version
HIPL_VER=1.0.8
ODTONE_VER=0.6
BOOST_VER=1_48_0

# empty for linux compilation
TOOLSET=
LDFLAGS=
ANDROID=

all: socks hip mih additional

socks:
	$(MAKE) -C ./middleware

hip:
	$(MAKE) -C ./protocols/hip/hipl-$(HIPL_VER)

mih:
	$(CD) ./protocols/mih/odtone-$(ODTONE_VER); $(BJAM) --boost-root=../boost_$(BOOST_VER) linkflags=-lpthread

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
	$(MAKE) install -C ./protocols/hip/hipl-$(HIPL_VER)/

clean:
	$(MAKE) -C ./middleware clean
	$(MAKE) -C ./protocols/hip/hipl-$(HIPL_VER) clean
	$(CD) ./protocols/mih/odtone-$(ODTONE_VER); $(BJAM) clean

