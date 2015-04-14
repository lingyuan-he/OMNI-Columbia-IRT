#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - HIP for Linux
# Lingyuan He - 04/2015

# for cross compile
INSTALL_PATH=$(pwd)/install
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-none-linux

# compiler and tool
#CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm

# software version
LIBMNL_VER=1.0.3
LIBNFNETLINK_VER=1.0.1
LIBNETFILTER_VER=1.0.2
HIPL_VER=1.0.8

# work folder
cd work

# libmnl
if [ ! -f libmnl-$LIBMNL_VER.tar.bz2 ]; then
	wget http://www.netfilter.org/projects/libmnl/files/libmnl-$LIBMNL_VER.tar.bz2
fi
bzip2 -dk libmnl-$LIBMNL_VER.tar.bz2
tar xvf libmnl-$LIBMNL_VER.tar
cd libmnl-$LIBMNL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST CFLAGS=-I$INSTALL_PATH/include LDFLAGS=-L$INSTALL_PATH/lib
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
make
make install
cd ../

# copy hipl and decompress
cp ../../protocols/hip/hipl-$HIPL_VER.tar.gz ./
tar zxvf hipl-$HIPL_VER.tar.gz

# compile hipl
cd hipl-$HIPL_VER
PKG_CONFIG_PATH=$INSTALL_PATH/lib/pkgconfig LDFLAGS="-L/usr/arm-linux-gnueabi/lib/ -L$INSTALL_PATH/lib" CPPFLAGS=-I$INSTALL_PATH/include LIBS="-ldl -lmnl -lnfnetlink -lnetfilter_queue" CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST
make
make install
cd ../

