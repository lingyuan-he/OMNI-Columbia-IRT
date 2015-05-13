#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - HIP for Linux
# Lingyuan He - 05/2015

# cross compile variables
INSTALL_PATH=$(pwd)/install
TOOLCHAIN_FOLDER=$(pwd)/toolchain
TOOLCHAIN=$TOOLCHAIN_FOLDER/bin/arm-linux-androideabi-
HOST=arm-linux

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
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST CFLAGS="-I$INSTALL_PATH/include" LDFLAGS="-L$INSTALL_PATH/lib" #-static
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
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --prefix=$INSTALL_PATH --host=$HOST CFLAGS="-I$INSTALL_PATH/include" LDFLAGS="-L$INSTALL_PATH/lib" #-static
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
# use patch from HIP
patch -N src/extra/tcp.c < ../../patches/libnetfilter_queue/tcp.c.patch
PKG_CONFIG_PATH=$INSTALL_PATH/lib/pkgconfig CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure  --prefix=$INSTALL_PATH --host=$HOST CFLAGS="-I$INSTALL_PATH/include" LDFLAGS="-L$INSTALL_PATH/lib" #-static
make
make install
cd ../


# hipl

# copy hipl and decompress
cp ../../protocols/hip/hipl-$HIPL_VER.tar.gz ./
tar zxvf hipl-$HIPL_VER.tar.gz

# compile hipl
cd hipl-$HIPL_VER
PKG_CONFIG_PATH=$INSTALL_PATH/lib/pkgconfig:$PKG_CONFIG_PATH ANDROID_SYSROOT=$TOOLCHAIN_FOLDER/sysroot LDFLAGS=-L$INSTALL_PATH/lib CFLAGS="-I$INSTALL_PATH/include -static -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_N -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -Wall -fPIC" CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./configure --enable-android --disable-android-pie --host=$HOST --prefix=$INSTALL_PATH/hipl
make
make install
cd ../

echo ""
echo "Cross compilation for hipl is done"
echo ""

