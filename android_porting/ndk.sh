#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - NDK Configuration
# Lingyuan He - 05/2015

# download, configure and patch NDK

# toolchain variables
TOOLCHAIN_FOLDER=$(pwd)/toolchain
TOOLCHAIN_SYSROOT=$TOOLCHAIN_FOLDER/sysroot

# NDK variables
NDK_VERSION=r10d
NDK_ROOT=$(pwd)/work/android-ndk-$NDK_VERSION
NDK_SYS=linux-x86 # use 32-bit version for compatibility
NDK_PLATFORM=android-14 # Icecream Sandwich and up, should support a lot of devices
NDK_GCC=4.9 # use gcc version 4.9

# work directory
cd work

# download 32-bit NDK for compatibility
if [ ! -f android-ndk-$NDK_VERSION-$NDK_SYS.bin ]; then
	wget https://dl.google.com/android/ndk/android-ndk-$NDK_VERSION-$NDK_SYS.bin
	chmod a+x android-ndk-$NDK_VERSION-$NDK_SYS.bin
fi
# extract only when directory not exist
if [ ! -d android-ndk-$NDK_VERSION ]; then
	./android-ndk-$NDK_VERSION-$NDK_SYS.bin
fi
# build toolchain
$NDK_ROOT/build/tools/make-standalone-toolchain.sh --toolchain=arm-linux-androideabi-$NDK_GCC --platform=$NDK_PLATFORM --arch=arm --ndk-dir=$NDK_ROOT --system=$NDK_SYS --install-dir=$TOOLCHAIN_FOLDER

# patch toolchain
# HIPL - add definition for __fswab64 needed by libnetfilter_queue
patch -N $TOOLCHAIN_SYSROOT/usr/include/linux/byteorder/swab.h < ../patch/ndk/swab.h.patch
# HIPL - add some deprecated stuff back to netinet/ip.h
patch -N $TOOLCHAIN_SYSROOT/usr/include/netinet/ip.h < ../patch/ndk/ip.h.patch
# HIPL - add the icmphdr definition to netinet/ip_icmp.h
patch -N $TOOLCHAIN_SYSROOT/usr/include/netinet/ip_icmp.h < ../patch/ndk/ip_icmp.h.patch
# ODTONE - ICMP6_FILTER definition
patch -N $TOOLCHAIN_SYSROOT/usr/include/netinet/icmp6.h < ../patch/ndk/icmp6.h.patch

echo ""
echo "NDK Version $NDK_VERSION is prepared and patched"
echo ""

