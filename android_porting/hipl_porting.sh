#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android HIP for Linux Cross Compile Script

# for cross compile
INSTALL_PATH=$(pwd)/install
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-none-linux

# compiler and tool
#CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm

# software version
OPENSSL_VER=1.0.2a
LIBMNL_VER=1.0.3
LIBNFNETLINK_VER=1.0.1
LIBNETFILTER_VER=1.0.2
HIPL_VER=1.0.8

# check cross compiler
if ! which arm-linux-gnueabi-gcc >/dev/null; then
	echo 'Error: cross compile toolchain arm-linux-gnueabi not found'
    exit
fi

# make install folder
mkdir -p install

# openssl
if [ ! -f openssl-$OPENSSL_VER.tar.gz ]; then
	wget http://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz
fi
tar zxvf openssl-$OPENSSL_VER.tar.gz
cd openssl-$OPENSSL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./config shared no-asm no-ssl2 no-ssl3 no-comp no-hw no-engine --prefix=$INSTALL_PATH
sed 's/-m64//g' -i Makefile # The arm compiler doesn't support -m64
make clean
make
make install
cd ../

# libmnl
if [ ! -f libmnl-$LIBMNL_VER.tar.bz2 ]; then
	wget http://www.netfilter.org/projects/libmnl/files/libmnl-$LIBMNL_VER.tar.bz2
fi
bzip2 -dk libmnl-$LIBMNL_VER.tar.bz2
tar xvf libmnl-$LIBMNL_VER.tar
cd libmnl-$LIBMNL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST CFLAGS=-I$INSTALL_PATH/include LDFLAGS=-L$INSTALL_PATH/lib
make clean
make
make install
cd ../

# libnfnetlink
if [ ! -f libnfnetlink-$LIBNFNETLINK_VER.tar.bz2 ]; then
	wget http://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-$LIBNFNETLINK_VER.tar.bz2
fi
bzip2 -dk libnfnetlink-$LIBNFNETLINK_VER.tar.bz2
tar xvf libnfnetlink-$LIBNFNETLINK_VER.tar
cd libnfnetlink-$LIBNFNETLINK_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST CFLAGS=-I$INSTALL_PATH/include LDFLAGS=-L$INSTALL_PATH/lib
make clean
make
make install
cd ../

# libnetfilter_queue
if [ ! -f libnetfilter_queue-$LIBNETFILTER_VER.tar.bz2 ]; then
	wget http://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-$LIBNETFILTER_VER.tar.bz2
fi
bzip2 -dk libnetfilter_queue-$LIBNETFILTER_VER.tar.bz2
tar xvf libnetfilter_queue-$LIBNETFILTER_VER.tar
cd libnetfilter_queue-$LIBNETFILTER_VER
PKG_CONFIG_PATH=$INSTALL_PATH/lib/pkgconfig CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure  --prefix=$INSTALL_PATH --host=$HOST CFLAGS=-I$INSTALL_PATH/include LDFLAGS=-L$INSTALL_PATH/lib
make clean
make
make install
cd ../

# copy hipl and decompress
cp ../protocols/hip/hipl-$HIPL_VER.tar.gz ./
tar zxvf hipl-$HIPL_VER.tar.gz

# compile hipl
cd hipl-$HIPL_VER
PKG_CONFIG_PATH=$INSTALL_PATH/lib/pkgconfig LDFLAGS="-L/usr/arm-linux-gnueabi/lib/ -L$INSTALL_PATH/lib" CPPFLAGS=-I$INSTALL_PATH/include LIBS="-ldl -lmnl -lnfnetlink -lnetfilter_queue" CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST
make clean
make
make install

