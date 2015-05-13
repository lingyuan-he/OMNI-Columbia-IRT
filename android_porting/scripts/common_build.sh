#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Common Dependency
# Lingyuan He - 05/2015

# cross compile variables
INSTALL_PATH=$(pwd)/install
TOOLCHAIN=$(pwd)/toolchain/bin/arm-linux-androideabi-

# software version
OPENSSL_VER=1.0.2a
ZLIB_VER=1.2.8

# work directory
cd work

# openssl, common dependency
if [ ! -f openssl-$OPENSSL_VER.tar.gz ]; then
	wget http://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz
fi
tar zxvf openssl-$OPENSSL_VER.tar.gz
cd openssl-$OPENSSL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld ./config shared no-asm --prefix=$INSTALL_PATH #no-shared
sed 's/-m64//g' -i Makefile # arm compiler doesn't support -m64
make
make install
cd ../

# zlib, common dependency
if [ ! -f zlib-$ZLIB_VER.tar.gz ]; then
	wget http://zlib.net/zlib-$ZLIB_VER.tar.gz
fi
tar zxvf zlib-$ZLIB_VER.tar.gz
cd zlib-$ZLIB_VER
CC=${TOOLCHAIN}gcc LD=${TOOLCHAIN}ld AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib ./configure --prefix=$INSTALL_PATH #--static
make
make install
cd ../

