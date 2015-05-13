#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Compile Middleware
# Lingyuan He - 05/2015

# for cross compile
INSTALL_PATH=$(pwd)/install
TOOLCHAIN_FOLDER=$(pwd)/toolchain
TOOLCHAIN=$TOOLCHAIN_FOLDER/bin/arm-linux-androideabi-
HOST=arm-linux

# software version
CURL_VER=7.41.0
WRAPPER_VER=7.6
ZLIB_VER=1.2.8

# work folder
cd work

# tcp wrapper

# download and decompress
if [ ! -f tcp_wrappers_$WRAPPER_VER.tar.gz ]; then
	wget ftp://ftp.porcupine.org/pub/security/tcp_wrappers_$WRAPPER_VER.tar.gz
fi
tar zxvf tcp_wrappers_$WRAPPER_VER.tar.gz
cd tcp_wrappers_$WRAPPER_VER

# apply patch to fix compilation error and add cross compilation support
patch -p0 < ../../patch/tcp_wrappers/tcp_wrappers.patch
CC=${TOOLCHAIN}gcc RANLIB=${TOOLCHAIN}ranlib make REAL_DAEMON_DIR=./ android
cp libwrap.a ../../install/lib
cp tcpd.h ../../install/include
cd ../


# curl

if [ ! -f curl-$CURL_VER.tar.gz ]; then
	wget http://curl.haxx.se/download/curl-$CURL_VER.tar.gz
fi
tar zxvf curl-$CURL_VER.tar.gz
cd curl-$CURL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm CPPFLAGS=-I$INSTALL_PATH/include LDFLAGS=-L$INSTALL_PATH/lib LIBS="-lz -lssl -lcrypto" ./configure --prefix=$INSTALL_PATH --host=$HOST #--enable-shared=no --enable-static=yes
make
make install
cd ../
#

# middleware

# copy
cp -a ../../middleware ./
cd middleware
make clean

# configure srelay
cd ./srelay/srelay-0.4.8b5
./configure

# patch crypt() usage and unnecessary lib
patch -p0 < ../../../../patch/middleware/auth-pwd.c.patch
patch -p0 < ../../../../patch/middleware/Makefile.srelay.patch
cd ../../
patch -p0 < ../../patch/middleware/Makefile.main.patch

# compile
TOOLSET=${TOOLCHAIN} LDFLAGS=-L${INSTALL_PATH}/lib  ANDROID=-I${INSTALL_PATH}/include make # -static

# copy output
cp sined ../../install/sine
cp kill_sined ../../install/sine
cp locsw ../../install/sine


echo ""
echo "Cross compilation for middleware is done"
echo ""

