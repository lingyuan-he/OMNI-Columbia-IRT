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

echo ""
echo "This script will compile odtone, hipl and middlware into 'install' folder"
echo ""

# make sure cross compile tools are installed
echo "Installing cross compilation tools, please enter your password if prompted"
sudo apt-get -y install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi

# make install and work folder
mkdir -p install
mkdir -p install/odtone
mkdir -p work

# enter work folder
cd work

# openssl, common dependency
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

# back to work
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

