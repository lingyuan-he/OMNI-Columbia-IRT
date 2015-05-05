#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Main Script
# Lingyuan He - 04/2015

# for cross compile
INSTALL_PATH=$(pwd)/install
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-none-linux

# software version
OPENSSL_VER=1.0.2a
ZLIB_VER=1.2.8

echo ""
echo "This script will compile odtone, hipl and middlware into 'install' folder"
echo ""

# make sure cross compile tools are installed
echo "Installing cross compilation tools, please enter your password if prompted"
sudo apt-get -y install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi

# make install and work folder
mkdir -p install
mkdir -p install/lib
mkdir -p install/odtone
mkdir -p install/sined
mkdir -p work

# copy pre-built libraries
cp /usr/arm-linux-gnueabi/lib/*.a ./install/lib
cp /usr/arm-linux-gnueabi/lib/libc.so ./install/lib

# enter work folder
cd work

# openssl, common dependency
if [ ! -f openssl-$OPENSSL_VER.tar.gz ]; then
	wget http://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz
fi
tar zxvf openssl-$OPENSSL_VER.tar.gz
cd openssl-$OPENSSL_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LD=${TOOLCHAIN}ld NM=${TOOLCHAIN}nm ./config no-shared no-asm no-ssl2 no-ssl3 no-comp no-hw no-engine --prefix=$INSTALL_PATH
sed 's/-m64//g' -i Makefile # The arm compiler doesn't support -m64
make clean
make
make install
cd ../

# zlib, common dependency
if [ ! -f zlib-$ZLIB_VER.tar.gz ]; then
	wget http://zlib.net/zlib-$ZLIB_VER.tar.gz
fi
tar zxvf zlib-$ZLIB_VER.tar.gz
cd zlib-$ZLIB_VER
CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib ./configure --prefix=$INSTALL_PATH --static
make
make install
cd ../

# back to main porting folder
cd ../

# odtone
./odtone_porting.sh

# hipl
./hipl_porting.sh

# middleware
./middleware_porting.sh

echo ""
echo "Do not forget to change interface MAC address in 'install/odtone/802_11/link_sap.conf' and 'install/odtone/lte/link_sap.conf'"
echo ""
echo "All done, please push 'install' folder up to android device"
echo ""

